"""Asking an authority for an RFC 3161 time stamp over a witness imprint (7.2 step 5.3).

Only the 32-byte imprint leaves the tenant. A token counts only if it verifies offline against the
roots the mandate pins (`sheaf_core.tsp`), so a misbehaving authority is recorded as not obtained,
with the reason, never trusted. An authority that does not answer is asked again with growing
delays, never faster than it asks, for a set period; then the witness lists it as not obtained.
"""

import hashlib
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from sheaf_core.tsp import check_token, request
from sheaf_core.witness import AuthorityResult

MAX_RESPONSE = 64 * 1024
"""A time-stamp response is a few kilobytes; anything far larger is not one."""


@dataclass(frozen=True)
class Stamp:
    result: AuthorityResult
    response: bytes | None
    """The response exactly as received, to store as `{authority}.tsr`; None if not obtained."""


class Stamper:
    def __init__(
        self,
        client: httpx.Client,
        *,
        retry_for: float = 6 * 3600,
        first_delay: float = 30,
        max_delay: float = 1800,
        min_interval: Mapping[str, float] | None = None,
        timeout: float = 30,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.retry_for, self.first_delay, self.max_delay = retry_for, first_delay, max_delay
        self.min_interval = dict(min_interval or {})
        self.timeout = timeout
        self.sleep, self.clock = sleep, clock
        self._exhausted: dict[str, str] = {}
        """Authorities that used up a whole retry window in this run, with the last reason. Each
        is tried once, without waiting, for every later witness in the run."""

    def stamp(self, authority: Mapping[str, Any], roots: Sequence[bytes], imprint: bytes) -> Stamp:
        """Ask one authority, as the mandate lists it, to stamp `imprint`."""
        name = authority["authority"]
        nonce = secrets.randbits(63)
        body = request(imprint, nonce)
        started, attempts, delay = self.clock(), 0, self.first_delay
        retry_for = 0 if name in self._exhausted else self.retry_for
        while True:
            attempts += 1
            reason, response, token = self._attempt(authority["url"], body, imprint, roots, nonce)
            if token is not None:
                self._exhausted.pop(name, None)
                result = AuthorityResult(
                    authority=name,
                    jurisdiction=authority["jurisdiction"],
                    obtained=True,
                    qualified=token.qualified,
                    gen_time=_rfc3339(token.gen_time),
                    token_sha256=hashlib.sha256(response).hexdigest(),
                )
                return Stamp(result, response)
            wait = max(delay, self.min_interval.get(name, 0))
            elapsed = self.clock() - started
            if elapsed + wait > retry_for:
                break
            self.sleep(wait)
            delay = min(delay * 2, self.max_delay)
        if name in self._exhausted:
            reason = f"{reason}; down earlier in this run, tried once"
        else:
            reason = f"{reason}; {attempts} attempts over {round(self.clock() - started)} s"
            self._exhausted[name] = reason
        result = AuthorityResult(
            authority=name,
            jurisdiction=authority["jurisdiction"],
            obtained=False,
            unavailable_reason=reason[:256],
        )
        return Stamp(result, None)

    def _attempt(self, url, body, imprint, roots, nonce):
        try:
            with self.client.stream(
                "POST",
                url,
                content=body,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=self.timeout,
            ) as reply:
                if reply.status_code != 200:
                    return f"HTTP {reply.status_code}", None, None
                response = bytearray()
                for chunk in reply.iter_bytes():
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE:
                        return "response too large", None, None
        except httpx.TimeoutException:
            return "timeout", None, None
        except httpx.HTTPError as error:
            return f"connection failed ({type(error).__name__})", None, None
        response = bytes(response)
        token, problems = check_token(response, imprint=imprint, roots=roots, nonce=nonce)
        if problems:
            return f"{problems[0].code}: {problems[0].detail}", None, None
        return "", response, token


def _rfc3339(moment: datetime) -> str:
    moment = moment.astimezone(UTC)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if moment.microsecond:
        text += f".{moment.microsecond:06d}".rstrip("0")
    return text + "Z"
