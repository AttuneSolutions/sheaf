"""`sheaf-admin`: what a tenant's people run against its gateway.

    sheaf-admin check FILE           build a mandate and check it offline, as the gateway would
                                     (`genesis check FILE` is the same)
    sheaf-admin propose FILE         check it, then stage it as a proposal (7.6): upload it and
                                     its trust files, and register it for an approver
    sheaf-admin proposals            the proposals waiting for an approver (--status, --chain)
    sheaf-admin withdraw SHA256      withdraw a pending proposal: its proposer, or an approver
    sheaf-admin approve SHA256       approve a proposal, signed in as yourself: show it, ask for
                                     the chain's name, commit its config.changed
    sheaf-admin whoami               the identity the gateway sees, as entries must name it

Every command but `check` reaches the gateway, and takes:

    --gateway     SHEAF_GATEWAY_URL     https://<gateway fqdn>
    --scope       SHEAF_GATEWAY_SCOPE   api://<application id>/.default
    --credential  SHEAF_CREDENTIAL      cli (default): the person signed in with `az login`;
                                        managed: this machine's or job's managed identity
                                        (AZURE_CLIENT_ID if user-assigned)
    --key-vault   SHEAF_KEY_VAULT_URL   propose: the vault holding the witness key, read with
                                        the same credential to check the witness key file

A proposer needs the gateway's `proposer` app role, or before the genesis to be its
SHEAF_BOOTSTRAP_CALLER, and may be a workload: where Conditional Access refuses `az login`, run
`propose` with a managed identity inside the network. An approver is always a person, signed in
as themselves; the approval page (`sheaf-approve`) does the same as `approve` from a browser.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from azure.core.exceptions import AzureError

from sheaf_admin.actions import NotApplied, approve, full, plain, propose
from sheaf_admin.client import GatewayClient, GatewayRefused
from sheaf_admin.staging import InputError, Staged, load
from sheaf_core.proposal import STATUSES

CREDENTIALS = ("cli", "managed")

HINTS = {
    "mandate_not_in_force": (
        "Staging a mandate needs the gateway's proposer app role or, before the genesis, to be\n"
        "its SHEAF_BOOTSTRAP_CALLER; or the chain's genesis is still waiting for its interim\n"
        "witness."
    ),
    "caller_unknown": (
        "Staging needs the gateway's proposer app role (before the genesis, its\n"
        "SHEAF_BOOTSTRAP_CALLER may stage too); approving needs a role or an id the mandate in\n"
        "force grants config.changed."
    ),
    "proposal_required": (
        "A mandate change is committed only as the approval of a proposal: stage it with\n"
        "sheaf-admin propose."
    ),
    "proposal_not_pending": (
        "The proposal is no longer pending: sheaf-admin proposals --status all shows what\n"
        "became of it."
    ),
    "proposal_exists": "That mandate is already proposed: sheaf-admin proposals shows it.",
    "four_eyes": (
        "Whoever proposed the change may not approve it under this mandate: someone else\n"
        "approves it."
    ),
    "mandate_pending": (
        "The last mandate change is waiting for its interim witness. Start the witness job,\n"
        "  az containerapp job start -g <resource group> -n <witness job>\n"
        "then propose this again."
    ),
    "trust_conflict": (
        "Another file is already stored at that path in trust/, and stored files never change.\n"
        "For a witness key, create a new key version in Key Vault and name it in the mandate."
    ),
    "gateway_starting": "The gateway is starting: wait a minute and run the same command again.",
    "gateway_halted": (
        "The chain is halted: see the gateway's log, and the deploy guide, section 12."
    ),
    "proposal_unknown": (
        "No chain this gateway serves has that proposal: sheaf-admin proposals --status all\n"
        "lists them by fingerprint."
    ),
    "proposal_mismatch": (
        "The entry is not the proposal's approval. Approve with sheaf-admin approve or the\n"
        "approval page, which build it from the proposal."
    ),
    "state_unavailable": "The gateway could not reach its own state: run the same command again.",
}


def credential(kind: str) -> Any:
    """`cli`: the person signed in to the Azure CLI. `managed`: the managed identity of the
    machine or job this runs on, so a workload can stage a change where Conditional Access
    refuses a person's `az login`."""
    if kind == "managed":
        from azure.identity import ManagedIdentityCredential

        return ManagedIdentityCredential(client_id=os.environ.get("AZURE_CLIENT_ID"))
    from azure.identity import AzureCliCredential

    return AzureCliCredential()


def connect(url: str, scope: str, kind: str) -> GatewayClient:
    """The gateway, as `credential(kind)`. A token is asked for with each request, so nothing is
    asked of Azure until a mandate has passed its offline check, and a person who reads a
    proposal for a long time before approving it is not sent an expired one: the credential
    keeps a token until it is near its expiry."""
    signed_in = credential(kind)

    def token() -> str:
        return signed_in.get_token(scope).token

    return GatewayClient(httpx.Client(timeout=120), url, token=token)


def vault_key(vault_url: str, key_id: str, kind: str) -> bytes:
    """The public key Key Vault holds as `key_id`, as the witness job will sign with it."""
    from sheaf_witness.signer import key_vault_signer

    return key_vault_signer(key_id, vault_url, credential(kind)).public_key_pem()


def _gateway_options(parser: argparse.ArgumentParser, *, vault: bool = False) -> None:
    parser.add_argument("--gateway", default=os.environ.get("SHEAF_GATEWAY_URL"))
    parser.add_argument("--scope", default=os.environ.get("SHEAF_GATEWAY_SCOPE"))
    parser.add_argument(
        "--credential",
        choices=CREDENTIALS,
        default=os.environ.get("SHEAF_CREDENTIAL") or "cli",
        help="cli: az login as yourself (default); managed: a managed identity",
    )
    if vault:
        parser.add_argument("--key-vault", default=os.environ.get("SHEAF_KEY_VAULT_URL"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sheaf-admin",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n", 1)[1],
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="build a mandate and check it offline").add_argument(
        "file", type=Path
    )
    genesis = commands.add_parser("genesis", help="a chain's first mandate: as check")
    actions = genesis.add_subparsers(dest="action", required=True)
    actions.add_parser("check", help="build and check it offline").add_argument("file", type=Path)

    staging = commands.add_parser("propose", help="check a mandate, then stage it")
    staging.add_argument("file", type=Path)
    staging.add_argument("--expires-in-days", type=int, help="1 to 90; the gateway's default 14")
    _gateway_options(staging, vault=True)

    listing = commands.add_parser("proposals", help="the proposals waiting for an approver")
    listing.add_argument("--chain")
    listing.add_argument("--status", choices=(*STATUSES, "all"), default="pending")
    _gateway_options(listing)

    withdrawing = commands.add_parser("withdraw", help="withdraw a pending proposal")
    withdrawing.add_argument("sha256")
    _gateway_options(withdrawing)

    approving = commands.add_parser("approve", help="approve a proposal as yourself")
    approving.add_argument("sha256")
    approving.add_argument("--yes", action="store_true", help="do not ask for the chain name")
    _gateway_options(approving)

    _gateway_options(commands.add_parser("whoami", help="who the gateway sees"))
    return parser


def _required(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    for name, variable in (
        ("gateway", "SHEAF_GATEWAY_URL"),
        ("scope", "SHEAF_GATEWAY_SCOPE"),
        ("key_vault", "SHEAF_KEY_VAULT_URL"),
    ):
        if hasattr(args, name) and not getattr(args, name):
            parser.error(f"--{name.replace('_', '-')} or {variable} is required")
    if hasattr(args, "gateway") and not args.gateway.startswith("https://"):
        parser.error("the gateway is reached over https://: your token goes with every request")
    if hasattr(args, "credential") and args.credential not in CREDENTIALS:
        parser.error(f"SHEAF_CREDENTIAL is one of {', '.join(CREDENTIALS)}")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    _required(parser, args)
    now = datetime.now(UTC)
    try:
        if args.command in ("check", "genesis"):
            return _check(load(args.file), now)
        gateway = connect(args.gateway, args.scope, args.credential)
        if args.command == "whoami":
            print(json.dumps(gateway.me()))
            return 0
        if args.command == "propose":
            return _propose(load(args.file), gateway, args, now)
        if args.command == "proposals":
            return _proposals(gateway, args)
        if args.command == "withdraw":
            found = gateway.withdraw(args.sha256)
            print(f"Withdrew {found['mandate']} ({found['chain']} {found['version']}).")
            return 0
        return _approve(gateway, args, now)
    except InputError as error:
        print(error, file=sys.stderr)
    except NotApplied as error:
        print(f"Not applied: {error}", file=sys.stderr)
        for problem in error.problems:
            print(f"  {problem.code}  {problem.path}  {problem.detail}", file=sys.stderr)
    except GatewayRefused as error:
        _refused(error)
    except httpx.HTTPError as error:
        print(f"Could not reach the gateway: {error}", file=sys.stderr)
        print("Whatever was stored is kept: run the same command again.", file=sys.stderr)
    except AzureError as error:
        print(f"Azure: {error}", file=sys.stderr)
    return 1


def _check(staged: Staged, now: datetime) -> int:
    problems = staged.check(now)
    for problem in problems:
        print(f"{problem.code}  {problem.path}  {problem.detail}")
    if problems:
        return 1
    print(f"{staged.chain}, mandate {staged.mandate['version']}, fingerprint {staged.fingerprint}")
    print("\nIn plain language", *plain(staged.mandate), sep="\n")
    print("\nIn full", *full(staged.mandate, staged.fingerprint), sep="\n")
    print("\nChecked offline, as a genesis: no problems. When it is proposed the gateway checks")
    print("it again against the chain: as a change to the mandate in force, that its")
    print("SHEAF_IDENTIFIERS matches personal_data, and who may stage and approve it.")
    return 0


def _propose(staged: Staged, gateway: GatewayClient, args: argparse.Namespace, now) -> int:
    proposal, created = propose(
        staged,
        gateway,
        vault_key=lambda key_id: vault_key(args.key_vault, key_id, args.credential),
        now=now,
        expires_in_days=args.expires_in_days,
    )
    done = "Proposed" if created else "Already proposed"
    print(f"{done} {proposal['chain']} {proposal['version']}.")
    print(f"  fingerprint  {proposal['mandate']}")
    print(f"  status       {proposal['status']}")
    print(f"  expires      {proposal['expires_at']}")
    print("An approver approves it in the approval page, or with:")
    print(f"  sheaf-admin approve {proposal['mandate']}")
    return 0


def _proposals(gateway: GatewayClient, args: argparse.Namespace) -> int:
    status = None if args.status == "all" else args.status
    found, unavailable = gateway.listing(chain=args.chain, status=status)
    for chain in unavailable:
        print(f"Not read: {chain} is starting or halted; try again shortly.", file=sys.stderr)
    if not found:
        print("No proposals.")
    for p in found:
        print(
            f"{p['chain']}  {p['version']}  {p['mandate']}  {p['status']}  "
            f"{p['proposed_by']['id']}  expires {p['expires_at']}"
        )
    return 0


def _approve(gateway: GatewayClient, args: argparse.Namespace, now: datetime) -> int:
    def confirm(text: str, chain: str) -> bool:
        print(text, end="\n\n")
        if args.yes:
            return True
        print(f"Approving cannot be undone. Type {chain} to approve it: ", end="", flush=True)
        return sys.stdin.readline().strip() == chain

    receipt = approve(args.sha256, gateway, confirm=confirm, now=lambda: datetime.now(UTC))
    if receipt.get("already"):
        print(
            f"You already approved {args.sha256}: seq {receipt['seq']}, {receipt['hash']}, "
            f"at {receipt['committed_at']}."
        )
        return 0
    print(
        f"Approved {args.sha256}: committed at seq {receipt['seq']}, {receipt['hash']}, "
        f"at {receipt['committed_at']}."
    )
    print("Next, start the witness job, so its interim witness puts the mandate in force:")
    print("  az containerapp job start -g <resource group> -n <witness job>")
    print("Until then the chain takes no other mandate change, and before its genesis is in")
    print("force it accepts nothing else.")
    return 0


def _refused(error: GatewayRefused) -> None:
    print(f"The gateway refused ({error.status}):", file=sys.stderr)
    problems = error.problems if isinstance(error.problems, list) else [error.problems]
    for problem in problems:
        if isinstance(problem, dict):
            problem = f"{problem.get('code')}  {problem.get('path')}  {problem.get('detail')}"
        print(f"  {problem}", file=sys.stderr)
    codes = [p.get("code") for p in problems if isinstance(p, dict)]
    for code in dict.fromkeys(codes):
        if code in HINTS:
            print(HINTS[code], file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
