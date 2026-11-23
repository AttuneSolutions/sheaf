"""A proposed mandate change (7.6), and the `config.changed` that approves it.

A proposal is a candidate mandate staged before anyone approves it. It is the gateway's own
state, kept in `gateway-state`, not a record entry: the record holds only what was committed.
Approving one is committing the `config.changed` built here, with the approver's own token.

The gateway builds the same draft, with a stand-in approver, to check a proposal against the
chain before anyone is asked to approve it; the approval page and `sheaf-admin approve` build it
for the person approving. One builder, so what was checked is what is committed.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from sheaf_core import SPEC
from sheaf_core.mandate import changed_parts, part_digests
from sheaf_core.times import format_timestamp

STATUSES = ("pending", "approved", "withdrawn", "expired", "superseded")
"""`superseded`: another mandate change was committed since it was staged, so the mandate it
was staged against is no longer the one it would replace."""

STAND_IN_APPROVER = "ps-" + "0" * 32
"""An approver for checking a proposal before anyone approves it: a valid identity under clear
and under pseudonymised identifiers alike, and nobody's."""


def approval_draft(
    proposal: Mapping[str, Any],
    *,
    approver: str,
    observed_at: datetime,
    role: str | None = None,
) -> dict[str, Any]:
    """The `config.changed` that approves `proposal`, submitted by `approver`, who names `role`
    where the policy grants mandate changes by app role rather than by id (5.1)."""
    chain, previous = proposal["chain"], proposal["previous"]
    approved_by = {"kind": "person", "id": approver}
    actor = {**approved_by, "role": role} if role else dict(approved_by)
    return {
        "spec": SPEC,
        "tenant": chain.split("/")[0],
        "chain": chain,
        "dossier": None,
        "type": "config.changed",
        "observed_at": format_timestamp(observed_at),
        "actor": actor,
        "artefacts": [dict(ref) for ref in proposal["artefacts"]],
        "body": {
            "version": proposal["version"],
            "previous": None
            if previous is None
            else {"version": previous["version"], "config": previous["config"]},
            "changed": list(proposal["changed"]),
            "mandate": proposal["mandate"],
            "parts": dict(proposal["parts"]),
            "proposed_by": dict(proposal["proposed_by"]),
            "approved_by": approved_by,
            "reason": proposal["reason"],
        },
    }


def shown_differs(
    proposal: Mapping[str, Any],
    mandate: Mapping[str, Any],
    previous_mandate: Mapping[str, Any] | None,
) -> list[str]:
    """What, if anything, differs between the mandates a client is about to show an approver
    (the proposed one and the one it replaces, as the gateway sent them) and what approving
    `proposal` commits. A client refuses to ask for an approval while anything does, so a person
    never signs other than what they read."""
    differ = []
    if mandate.get("chain") != proposal["chain"]:
        differ.append("chain")
    if mandate.get("version") != proposal["version"]:
        differ.append("version")
    try:
        if part_digests(mandate) != proposal["parts"]:
            differ.append("parts")
        if changed_parts(previous_mandate, mandate) != list(proposal["changed"]):
            differ.append("changed")
    except (KeyError, TypeError, ValueError):
        differ.append("parts")
    if (previous_mandate is None) != (proposal["previous"] is None):
        differ.append("previous")
    return differ
