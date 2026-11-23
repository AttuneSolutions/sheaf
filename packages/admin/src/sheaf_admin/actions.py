"""Staging a mandate change as a proposal, and approving one (7.6).

A mandate change, the genesis included, is two steps by two sign-ins where the mandate asks for
four eyes. A proposer stages it: `propose` checks it offline, makes sure the witness key file is
the key the vault holds, uploads it with its trust files, and registers the proposal, which the
gateway checks against the chain. An approver approves it: `approve` shows what it is, in plain
language and in full, asks them to confirm, and commits its `config.changed` with their own
token. Neither can be taken back once the container is locked, so each stops before writing
anything at the first doubt. What is stored stays stored and the same bytes are accepted again,
so a run that stopped partway is finished by running it again.
"""

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import serialization

from sheaf_admin.client import GatewayClient
from sheaf_admin.staging import Staged
from sheaf_core.describe import describe, diff, technical
from sheaf_core.problems import Problem
from sheaf_core.proposal import approval_draft, shown_differs


class NotApplied(Exception):
    """Stopped before writing anything."""

    def __init__(self, reason: str, problems: list[Problem] | None = None):
        super().__init__(reason)
        self.problems = problems or []


def propose(
    staged: Staged,
    gateway: GatewayClient,
    *,
    vault_key: Callable[[str], bytes],
    now: datetime,
    expires_in_days: int | None = None,
) -> tuple[dict[str, Any], bool]:
    """Stage `staged`: its uploads, its trust files, then the proposal. Returns the proposal,
    and whether it is new. Raises NotApplied, before anything is written, if the mandate has
    problems or its witness key file is not the key in the vault; GatewayRefused if the gateway
    refuses."""
    problems = staged.check(now)
    if problems:
        raise NotApplied("the mandate has problems", problems)
    gateway.me()
    # Whoever may stage may read the chain's proposals: asking first refuses a caller who may
    # not stage before anything is uploaded, rather than after.
    gateway.proposals(chain=staged.chain)
    key_id = staged.witness_key_id()
    if not _same_key(vault_key(key_id), staged.witness_key_pem()):
        raise NotApplied(
            f"the witness key file is not {key_id} in the vault: its interim witness would never "
            "verify, the mandate would never apply, and the chain would take no other change"
        )
    for upload in staged.uploads:
        gateway.upload(staged.chain, upload)
    for path, data in staged.trust.items():
        gateway.put_trust(path, data)
    return gateway.propose(staged.request(expires_in_days=expires_in_days))


def approve(
    sha256: str,
    gateway: GatewayClient,
    *,
    confirm: Callable[[str, str], bool],
    now: datetime | Callable[[], datetime],
) -> dict[str, Any]:
    """Approve the proposal of the mandate with this SHA-256: commit its `config.changed` as the
    person signed in. `confirm` is shown what is approved and the chain's name, and says whether
    to go on. Returns the gateway's receipt, with `already` set if this person had approved it
    before. Raises NotApplied, before anything is written, if the caller is not a person or may
    not approve it, or does not confirm, or if what it would show is not what it would commit;
    GatewayRefused if the gateway refuses. `now` may be a clock, read once the person has
    confirmed, so the approval's `observed_at` is when they approved."""
    me = gateway.me()
    if me.get("person") is not True:
        raise NotApplied(
            "signed in as an application: an approver signs in as a person, with their own "
            "account (5.1)"
        )
    view = gateway.proposal(sha256)
    proposal, caller = view["proposal"], view["caller"]
    if proposal["mandate"] != sha256:
        raise NotApplied(f"the gateway answered with another proposal, {proposal['mandate']}")
    if proposal["status"] == "approved":
        approved = proposal.get("approved") or {}
        if (approved.get("by") or {}).get("id") == me["id"]:
            return {"already": True, **{k: approved[k] for k in ("seq", "hash", "committed_at")}}
        by = (approved.get("by") or {}).get("id", "someone else")
        raise NotApplied(f"the proposal was approved already, by {by}")
    if not caller.get("may_approve"):
        code = caller.get("refusal_code") or "not_an_approver"
        refusal = caller.get("refusal") or "you may not approve this proposal"
        raise NotApplied(refusal, [Problem(code, "$", refusal)])
    differ = shown_differs(proposal, view["mandate"], view["previous_mandate"])
    if differ:
        raise NotApplied(
            "the mandate the gateway sent differs from the proposal in "
            f"{', '.join(differ)}: nothing is shown or written"
        )
    if not confirm(render(view), proposal["chain"]):
        raise NotApplied("not confirmed: nothing was written")
    observed_at = now() if callable(now) else now
    draft = approval_draft(
        proposal, approver=me["id"], role=caller.get("role"), observed_at=observed_at
    )
    return gateway.commit(draft)


def render(view: Mapping[str, Any]) -> str:
    """A proposal as its approver reads it: who proposed what and why, what changes, the whole
    mandate in plain language, and the mandate in full."""
    proposal, doc, old = view["proposal"], view["mandate"], view["previous_mandate"]
    previous = proposal["previous"]
    proposer = proposal["proposed_by"]
    replaces = (
        "the chain's genesis: its first mandate"
        if previous is None
        else f"replaces {previous['version']} ({previous['config']})"
    )
    rows = [
        ("fingerprint", proposal["mandate"]),
        ("chain", proposal["chain"]),
        ("version", f"{proposal['version']}, {replaces}"),
        ("proposed by", f"{proposer['id']} ({proposer['kind']}) at {proposal['proposed_at']}"),
        ("reason", proposal["reason"]),
        ("expires", proposal["expires_at"]),
        ("status", proposal["status"]),
    ]
    lines = [f"Proposal {proposal['mandate']}"]
    lines += [f"  {name:<12} {value}" for name, value in rows]
    lines += ["", "What changes"]
    if old is None:
        lines.append("  Everything: this is the chain's first mandate, shown whole below.")
    else:
        for change in diff(old, doc):
            lines.append(f"  {change['title']}")
            lines += [f"    was: {line}" for line in change["removed"]]
            lines += [f"    now: {line}" for line in change["added"]]
    lines += ["", "The whole mandate", *plain(doc)]
    lines += ["", "In full", *full(doc, proposal["mandate"])]
    return "\n".join(lines)


def plain(doc: Mapping[str, Any]) -> list[str]:
    """A mandate in plain language, a heading for each part."""
    lines = []
    for section in describe(doc):
        lines.append(f"  {section['title']}")
        lines += [f"    {line}" for line in section["lines"]]
    return lines


def full(doc: Mapping[str, Any], sha256: str) -> list[str]:
    """A mandate as an engineer checks it, digests in full."""
    return [f"  {name:<17} {value}" for name, value in technical(doc, sha256)]


def _same_key(first: bytes, second: bytes) -> bool:
    try:
        keys = [serialization.load_pem_public_key(pem) for pem in (first, second)]
        return keys[0].public_numbers() == keys[1].public_numbers()
    except (ValueError, TypeError, AttributeError):
        return False
