"""`sheaf-admin`: what a tenant's people run against its gateway.

    sheaf-admin genesis check FILE   build a chain's genesis and check it offline, as the gateway
                                     would
    sheaf-admin genesis apply FILE   check it, then send it, signed in as its approver
    sheaf-admin whoami               the identity the gateway sees, as entries must name it

`apply` and `whoami` sign in through the Azure CLI, so `az login` as yourself first, and take:

    --gateway    SHEAF_GATEWAY_URL     https://<gateway fqdn>
    --scope      SHEAF_GATEWAY_SCOPE   api://<application id>/.default
    --key-vault  SHEAF_KEY_VAULT_URL   the vault holding the witness key (apply)
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from azure.core.exceptions import AzureError

from sheaf_admin.genesis import (
    GatewayClient,
    GatewayRefused,
    InputError,
    NotApplied,
    apply,
    load,
)


def connect(url: str, scope: str) -> GatewayClient:
    """The gateway, as the person signed in to the Azure CLI. The token is fetched when first
    needed, so nothing is asked of Azure until the genesis has passed its offline check."""
    from azure.identity import AzureCliCredential

    credential, cached = AzureCliCredential(), []

    def token() -> str:
        if not cached:
            cached.append(credential.get_token(scope).token)
        return cached[0]

    return GatewayClient(httpx.Client(timeout=120), url, token=token)


def vault_key(vault_url: str, key_id: str) -> bytes:
    """The public key Key Vault holds as `key_id`, as the witness job will sign with it."""
    from azure.identity import AzureCliCredential

    from sheaf_witness.signer import key_vault_signer

    return key_vault_signer(key_id, vault_url, AzureCliCredential()).public_key_pem()


def _gateway_options(parser: argparse.ArgumentParser, *, vault: bool) -> None:
    parser.add_argument("--gateway", default=os.environ.get("SHEAF_GATEWAY_URL"))
    parser.add_argument("--scope", default=os.environ.get("SHEAF_GATEWAY_SCOPE"))
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
    genesis = commands.add_parser("genesis", help="a chain's first mandate")
    actions = genesis.add_subparsers(dest="action", required=True)
    actions.add_parser("check", help="build and check it offline").add_argument("file", type=Path)
    send = actions.add_parser("apply", help="check it, then send it as its approver")
    send.add_argument("file", type=Path)
    _gateway_options(send, vault=True)
    send.add_argument("--yes", action="store_true", help="do not ask for the chain name")
    _gateway_options(commands.add_parser("whoami", help="who the gateway sees"), vault=False)
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
        parser.error("the gateway is reached over https://: the approver's token goes with it")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    _required(parser, args)
    try:
        if args.command == "whoami":
            print(json.dumps(connect(args.gateway, args.scope).me()))
            return 0
        genesis = load(args.file)
        now = datetime.now(UTC)
        if args.action == "check":
            return _check(genesis, now)
        return _apply(genesis, args, now)
    except InputError as error:
        print(error, file=sys.stderr)
    except NotApplied as error:
        print(f"Not applied: {error}", file=sys.stderr)
        for problem in error.problems:
            print(f"  {problem.code}  {problem.path}  {problem.detail}", file=sys.stderr)
    except GatewayRefused as error:
        print(f"The gateway refused ({error.status}):", file=sys.stderr)
        for problem in error.problems if isinstance(error.problems, list) else [error.problems]:
            if isinstance(problem, dict):
                problem = f"{problem.get('code')}  {problem.get('path')}  {problem.get('detail')}"
            print(f"  {problem}", file=sys.stderr)
        codes = [p.get("code") for p in error.problems if isinstance(p, dict)]
        if "mandate_not_in_force" in codes:
            print(
                "Either you are not the gateway's SHEAF_BOOTSTRAP_CALLER, or the chain already "
                "has its genesis,\nperhaps from an earlier apply that stopped after committing.",
                file=sys.stderr,
            )
    except httpx.HTTPError as error:
        print(f"Could not reach the gateway: {error}", file=sys.stderr)
        print("Whatever was stored is kept: run the same command again.", file=sys.stderr)
    except AzureError as error:
        print(f"Azure: {error}", file=sys.stderr)
    return 1


def _check(genesis, now: datetime) -> int:
    problems = genesis.check(now)
    for problem in problems:
        print(f"{problem.code}  {problem.path}  {problem.detail}")
    if problems:
        return 1
    print(genesis.summary())
    print("\nChecked offline: no problems. The gateway also checks that the approver is its")
    print("SHEAF_BOOTSTRAP_CALLER and that its SHEAF_IDENTIFIERS matches personal_data.")
    return 0


def _apply(genesis, args: argparse.Namespace, now: datetime) -> int:
    def confirm(summary: str) -> bool:
        print(summary, end="\n\n")
        if args.yes:
            return True
        print(
            f"A genesis cannot be undone. Type {genesis.chain} to commit it: ",
            end="",
            flush=True,
        )
        return sys.stdin.readline().strip() == genesis.chain

    receipt = apply(
        genesis,
        connect(args.gateway, args.scope),
        vault_key=lambda key_id: vault_key(args.key_vault, key_id),
        confirm=confirm,
        now=now,
    )
    print(
        f"Committed the genesis of {genesis.chain}: seq {receipt['seq']}, {receipt['hash']}, "
        f"at {receipt['committed_at']}."
    )
    print("Next, start the witness job, so its interim witness puts the mandate in force:")
    print("  az containerapp job start -g <resource group> -n <witness job>")
    print("Until then the gateway accepts nothing else on this chain.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
