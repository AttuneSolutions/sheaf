# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

Sheaf: the evidence dossier standard (`docs/standard.md`, spec id `sheaf/1`), the write gateway,
the witness, the admin tool (`sheaf-admin`: mandates staged as proposals), the approval page
(`sheaf-approve`) and the offline verifier. Public, Apache-2.0. The standard is the source of truth;
when code and standard disagree, fix one of them in the same change.

## Stack

Python 3.12, a [uv](https://docs.astral.sh/uv/) workspace. Each part is a package under
`packages/`. Deployed as one container image (multi-arch, `linux/arm64` and `linux/amd64`), run
on Azure Container Apps: the gateway as an app, the witness as a scheduled job (standard 7.1).

```bash
uv sync
uv run pytest                                  # all tests
uv run pytest packages/core/tests/test_chain.py
uv run ruff check . && uv run ruff format --check .
uv add --package sheaf-core <dep>              # add a dependency to one package
```

## Rules that are easy to break

- **`sheaf-core` has no Azure, network or I/O dependencies.** The verifier uses it and promises to
  run offline on a downloaded copy of a container, with nothing from Microsoft beyond reading Blob.
  Azure SDKs belong in `gateway`, `witness` and `admin` only. `approve` has none either: it acts
  only with the approver's own token, relayed to the gateway.
- **One implementation of the hash rules.** The gateway and the verifier both call
  `sheaf_core.canonical` and `sheaf_core.digest`. Never canonicalise or hash an entry anywhere
  else: a second implementation is how a writer and its checker drift apart.
- **One implementation of the rules.** Entry, artefact, witness and mandate checks, and the rules
  that need the chain (`sheaf_core.rules.ChainState`), live in core so the verifier replays exactly
  what the gateway enforced. The gateway decides only who the caller is and where bytes go.
- **The registry JSON Schemas are the source** (`packages/core/src/sheaf_core/registry/`). Edit the
  JSON; they are copied as they are into tenants' containers. Write `{"not": {}}`, not `false`, for
  a property that may not appear: jsonschema drops the error path of a `false` subschema.
- **Named time-stamp authorities live in `packages/witness` (`authorities.json`), never in the
  standard.** The standard only says a mandate names two or more in two or more jurisdictions.
  Tokens are checked by `sheaf_core.tsp` alone, against roots the mandate pins.
- **Integers only in entries** (standard 5.2). A fraction is a string.
- **No customer information** in code, tests, fixtures, docs or commit messages. Examples use the
  tenant `acme` and the workflow `case-review`. The repository is public.
- **Validate and reject; never transform.** The gateway stores exactly the bytes it was given.
- Tests come first. Write the failing test, then the code. Build examples with
  `sheaf_core.testing` (tenant `acme`, workflow `case-review`) so every package builds them alike.

## Writing

Plain hyphens, not em or en dashes. British spelling (artefact, organisation).
