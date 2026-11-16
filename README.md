<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/sheaf-dark.svg">
    <img src="docs/logo/sheaf.svg" alt="Sheaf logo" width="160">
  </picture>
</p>

# Sheaf

An evidence record for automated workflows that the customer holds, that one gateway writes,
and that anyone can check without us.

Each unit of work produces a **dossier**: an ordered, hash-chained list of entries pointing to
content-addressed artefacts (documents, AI requests and responses, traces, decisions). A write
gateway running in the customer's own Azure subscription validates every artefact and entry
before committing it to write-once Blob storage. A daily witness, signed by a key the gateway
cannot use and time-stamped by two independent RFC 3161 authorities in different
jurisdictions, anchors the chain. An open verifier checks the whole record offline.

**Status:** pre-release. The standard is draft 0.2 and nothing has been written under it.

Read the standard at **https://attunesolutions.github.io/sheaf/**.

## Layout

| Path | What |
|---|---|
| [`docs/standard.md`](docs/standard.md) | The Sheaf evidence dossier standard, `sheaf/1` |
| `packages/core` | Canonical JSON, digests, the chain, the registry's JSON Schemas, entry and artefact checks, the witness format and signature, RFC 3161 token checks, and the rules that need the chain. Shared by the gateway and the verifier. No Azure dependencies |
| `packages/core/src/sheaf_core/registry` | The kind registry and every JSON Schema (2020-12) in force, as copied into a tenant's container |
| `packages/gateway` | The write gateway: FastAPI upload and commit endpoints (Azure Blob store with locked per-blob retention, chain-head lease, write-ahead journal and recovery on start; callers authenticated by Entra ID access tokens, v2, validated against the tenant's keys). Witnesses are submitted with their tokens to `POST /v1/witnesses`; trust files to `PUT /v1/trust/...` |
| `Dockerfile` | One image for every workload, `linux/amd64` and `linux/arm64` |
| `packages/witness` | The witness: the catalogue of time-stamp authorities and the free default (FreeTSA, Sectigo, DigiCert), the RFC 3161 client, the signer and witness assembly and the scheduled job (`python -m sheaf_witness`), which follows the chain, signs with Key Vault and submits to the gateway. No revocation capture or interim-after-seal yet |
| `packages/verifier` | The offline verifier (to come) |

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync                 # install the workspace
uv run pytest           # run all tests
uv run ruff check .     # lint
uv run ruff format .    # format
docker buildx build --platform linux/amd64,linux/arm64 -t sheaf:dev .
```

The image is published to GitHub Container Registry by `.github/workflows/release.yml`: every push
to `main` moves `:edge`, and a `v*.*.*` tag publishes that version and `latest` and cuts a GitHub
Release naming the digest. A mandate records that digest, so the build is reproducible from the
commit; the release notes give the command to rebuild it.

## Licence and attribution

Apache License 2.0; see [LICENSE](LICENSE).

The standard is aligned with MIO-STD-01 v0.2 clauses 4.1-4.4, 4.6.4, 5.1-5.3, 5.6-5.8, 6.1-6.3,
6.5 and 8.4 (J. G. Stroh, CC BY 4.0). It does not claim conformance with MIO-STD-01, and the
author of MIO-STD-01 does not endorse it.
