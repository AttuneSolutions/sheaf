"""The witness format (section 5.2): what is signed, what is stamped, and the time attestation.

- The **signing input** is the RFC 8785 canonical witness without `signature` and
  `time_attestation`. The witness identity signs it with the witness key; the gateway never can.
- The **imprint** is the SHA-256 of the RFC 8785 canonical witness without `time_attestation`,
  so it covers the signature. Its 32 bytes are all that is sent to the time-stamp authorities.
- The **time attestation** lists every authority asked, attested or not, and three facts derived
  from that list. `qualified` is read from each token by whoever parsed it; nothing here parses
  tokens, and nothing here holds a key: this package never verifies a signature or a token.
"""

import base64
import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import time, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from sheaf_core import paths
from sheaf_core.canonical import canonicalize
from sheaf_core.digest import PREFIX, canonical_digest
from sheaf_core.problems import Problem
from sheaf_core.schema import validate
from sheaf_core.times import parse_timestamp
from sheaf_core.tsp import check_token

SCHEMA_ID = "sheaf.witness/1"
_MIDNIGHT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z")
IMPRINT_OVER = "RFC 8785 canonical witness without time_attestation"


def signing_input(witness: Mapping[str, Any]) -> bytes:
    """The bytes the witness key signs. The same before and after signing."""
    return canonicalize(
        {k: v for k, v in witness.items() if k not in ("signature", "time_attestation")}
    )


def imprint(witness: Mapping[str, Any]) -> str:
    """ "sha256:" and the SHA-256 of the canonical witness without `time_attestation`."""
    if "signature" not in witness:
        raise ValueError("a witness is stamped only after it is signed: no signature")
    return canonical_digest({k: v for k, v in witness.items() if k != "time_attestation"})


def imprint_bytes(witness: Mapping[str, Any]) -> bytes:
    """The 32-byte message imprint for an RFC 3161 request."""
    return bytes.fromhex(imprint(witness).removeprefix(PREFIX))


@dataclass(frozen=True)
class AuthorityResult:
    """One authority asked for a stamp: a token, or the reason there is none."""

    authority: str
    jurisdiction: str
    obtained: bool
    qualified: bool | None = None
    gen_time: str | None = None
    token_sha256: str | None = None
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        stamped = (self.qualified, self.gen_time, self.token_sha256)
        if self.obtained:
            if None in stamped or self.unavailable_reason is not None:
                raise ValueError(
                    f"{self.authority}: an obtained stamp has qualified, gen_time and "
                    "token_sha256, and no unavailable_reason"
                )
        elif self.unavailable_reason is None or any(v is not None for v in stamped):
            raise ValueError(
                f"{self.authority}: a stamp not obtained has an unavailable_reason and "
                "nothing read from a token"
            )

    def as_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "authority": self.authority,
            "jurisdiction": self.jurisdiction,
            "obtained": self.obtained,
        }
        if self.obtained:
            result.update(
                qualified=self.qualified, gen_time=self.gen_time, token_sha256=self.token_sha256
            )
        else:
            result["unavailable_reason"] = self.unavailable_reason
        return result


def summarise(authorities: Sequence[AuthorityResult | Mapping[str, Any]]) -> dict[str, Any]:
    """The facts derived from the authorities listed.

    `distinct_jurisdictions` is true exactly when two or more authorities attested from two or
    more jurisdictions. It is not a claim that no single order or treaty reaches both.
    """
    attested = [_as_json(a) for a in authorities if _as_json(a)["obtained"]]
    jurisdictions = sorted({a["jurisdiction"] for a in attested})
    return {
        "attested_count": len(attested),
        "attested_jurisdictions": jurisdictions,
        "distinct_jurisdictions": len(jurisdictions) >= 2,
    }


def time_attestation(
    witness: Mapping[str, Any], authorities: Sequence[AuthorityResult]
) -> dict[str, Any]:
    """The `time_attestation` block for a signed witness, listing every authority asked."""
    return {
        "imprint": imprint(witness),
        "imprint_over": IMPRINT_OVER,
        "authorities": [a.as_json() for a in authorities],
        **summarise(authorities),
    }


def check_witness(witness: Any, path: str = "$") -> list[Problem]:
    """Everything about a witness that can be checked without the chain or a key."""
    problems = validate(SCHEMA_ID, witness, path)
    if problems:
        return problems

    block = witness["time_attestation"]
    if block["imprint"] != imprint(witness):
        problems.append(
            Problem(
                "imprint_mismatch",
                f"{path}.time_attestation.imprint",
                "the imprint is not over this witness: it was changed after it was stamped",
            )
        )

    for field, expected in summarise(block["authorities"]).items():
        if block[field] != expected:
            problems.append(
                Problem(
                    "attestation_inconsistent",
                    f"{path}.time_attestation.{field}",
                    f"{block[field]!r}, but the authorities listed give {expected!r}",
                )
            )

    seen: set[str] = set()
    for index, authority in enumerate(block["authorities"]):
        if authority["authority"] in seen:
            problems.append(
                Problem(
                    "authority_duplicate",
                    f"{path}.time_attestation.authorities[{index}]",
                    f"{authority['authority']} is listed twice",
                )
            )
        seen.add(authority["authority"])

    if witness["witness"] == "daily":
        bounds = witness["interval"]["from"], witness["interval"]["to"]
        start, end = (parse_timestamp(bound) for bound in bounds)
        # Written exactly, so no verifier's timestamp precision can change the answer.
        exact = all(_MIDNIGHT.fullmatch(bound) for bound in bounds)
        if not exact or start.time() != time(0) or end - start != timedelta(days=1):
            problems.append(
                Problem(
                    "interval_invalid",
                    f"{path}.interval",
                    "a daily interval is one UTC day, written YYYY-MM-DDT00:00:00Z to the next",
                )
            )
    return problems


def _as_json(authority: AuthorityResult | Mapping[str, Any]) -> Mapping[str, Any]:
    return authority.as_json() if isinstance(authority, AuthorityResult) else authority


# -- the witness signature (5.2, 7.5) ---------------------------------------------------------


def sign_es256(key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    """An ES256 signature over `data`, as JOSE writes it: r and s as 32 bytes each, in base64url
    without padding. The witness signs with a Key Vault key it cannot export; this is for a key
    held in memory, as in tests and development."""
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def public_key_sha256(pem: bytes) -> str:
    """How the mandate names the witness key: the SHA-256 of `trust/witness-keys/{key_id}.pem`."""
    return hashlib.sha256(pem).hexdigest()


def verify_signature(
    witness: Mapping[str, Any], public_key_pem: bytes, path: str = "$"
) -> list[Problem]:
    """Whether the witness's signature verifies with the witness key (an EC P-256 public key, PEM)
    over its signing input."""
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as error:
        return [Problem("witness_key_invalid", path, f"the witness key cannot be read: {error}")]
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        return [Problem("witness_key_invalid", path, "the witness key is an EC P-256 key (ES256)")]
    signature = witness.get("signature", "")
    try:
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    except (ValueError, TypeError):
        raw = b""
    if len(raw) != 64:
        return [Problem("witness_signature", f"{path}.signature", "an ES256 signature is 64 bytes")]
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, signing_input(witness), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return [Problem("witness_signature", f"{path}.signature", "the signature does not verify")]
    return []


def check_attestation(
    witness: Mapping[str, Any],
    mandate: Mapping[str, Any],
    *,
    tokens: Mapping[str, bytes],
    trust: Callable[[str], bytes | None],
    path: str = "$",
) -> list[Problem]:
    """What the gateway checks before it commits a witness, and the verifier checks again (7.2
    step 5, 9): the signature, with the witness key the mandate pins in `trust/witness-keys/`;
    and each token the witness lists as obtained, which must be the one supplied, verify against
    the roots the mandate pins in `trust/tsa/`, and say what the witness says it says. `witness`
    must already have passed `check_witness`."""
    problems: list[Problem] = []
    key = mandate["witness_key"]
    key_path = paths.witness_key(key["key_id"])
    pem = trust(key_path)
    if pem is None or hashlib.sha256(pem).hexdigest() != key["public_key_sha256"]:
        problems.append(Problem("trust_missing", path, f"{key_path} is not the key pinned"))
    else:
        problems += verify_signature(witness, pem, path)

    imprint = imprint_bytes(witness)
    pinned = {listed["authority"]: listed["roots"] for listed in mandate["authorities"]["list"]}
    obtained = set()
    for index, result in enumerate(witness["time_attestation"]["authorities"]):
        here, name = f"{path}.time_attestation.authorities[{index}]", result["authority"]
        token = tokens.get(name)
        if not result["obtained"]:
            if token is not None:
                problems.append(Problem("token_unexpected", here, f"{name} did not attest"))
            continue
        obtained.add(name)
        if token is None:
            problems.append(Problem("token_missing", here, f"no token from {name}"))
            continue
        if hashlib.sha256(token).hexdigest() != result["token_sha256"]:
            problems.append(Problem("token_mismatch", here, "not the token the witness lists"))
            continue
        roots = []
        for sha256 in pinned.get(name, []):
            certificate_path = paths.tsa_certificate(name, sha256)
            der = trust(certificate_path)
            if der is None or hashlib.sha256(der).hexdigest() != sha256:
                problems.append(Problem("trust_missing", here, f"{certificate_path} is missing"))
                break
            roots.append(der)
        else:
            stamp, found = check_token(token, imprint=imprint, roots=roots, path=here)
            problems += found
            if stamp is not None:
                if stamp.gen_time != parse_timestamp(result["gen_time"]):
                    problems.append(Problem("token_time_mismatch", here, "not the token's time"))
                if stamp.qualified != result["qualified"]:
                    problems.append(
                        Problem("token_qualified_mismatch", here, "read it from the token")
                    )
    for name in sorted(
        set(tokens)
        - obtained
        - {r["authority"] for r in witness["time_attestation"]["authorities"]}
    ):
        problems.append(
            Problem("token_unexpected", f"{path}.tokens.{name}", f"{name} is not listed")
        )
    return problems
