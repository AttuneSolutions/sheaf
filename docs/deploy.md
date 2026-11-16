# Deploying Sheaf

How to deploy Sheaf for one tenant in its own Azure subscription: the storage, the witness key, the
identities, the gateway, the witness job, the checks before anything is locked, and the first
entry. Sections of [the standard](standard.md) are cited by number.

Examples use the tenant `acme`, the workflow `case-review` and names in angle brackets, such as
`<rg>`, for values you choose. Commands are the Azure CLI, run by someone who can create resources
and role assignments in the subscription and app registrations in Entra ID.

**Status:** written for `v0.1.0` of the image. Section 13 lists what is not built yet; read it
before you plan a go-live date.

## 1 What gets deployed

| Resource | Purpose |
|---|---|
| Resource group | Everything below, in the tenant's region |
| Virtual network | A subnet for the Container Apps environment and one for private endpoints |
| Storage account | The `evidence` container (version-level immutability) and the mutable `gateway-state` container (7.1) |
| Key Vault | The witness key: EC P-256, not exportable (7.5) |
| Log Analytics workspace | Container logs and the Key Vault audit log, which the gateway's identity cannot write |
| Container Apps environment | Internal only: reachable from the virtual network, not the internet |
| Gateway app | One per workflow, one replica each (7.1) |
| Witness job | A scheduled job from the same image, with its own identity (7.5) |
| Entra ID app registration | The gateway's API: the audience callers ask for tokens to, and its app roles |
| Two managed identities | The gateway's and the witness's, never shared |

There is no reverse proxy in front of the gateway. The environment's built-in ingress terminates
TLS and, set to internal, admits only callers inside the virtual network. A second proxy would be
one more thing that sees every artefact and every caller's token. If a caller must reach the
gateway from outside the network, put an Azure-managed front door in front of it (Application
Gateway with WAF, or Front Door Premium over Private Link) rather than a proxy you run yourself.

## 2 Decide first

These go into the genesis mandate (5.6). Some cannot change once the tenant has written its first
entry; the rest change only through a `config.changed`.

- **Region:** where the record lives. Everything below is created there.
- **Workflows:** each workflow is one chain and one gateway app (`acme/case-review`).
- **Retention classes:** for example `regulated-record` for `P7Y` and `working-file` for `P1Y`.
  The longest class sets how long chain-level blobs are kept (4).
- **Identifiers:** `clear` or `pseudonymised` (5.7). In clear, people are recorded by their Entra
  object ID, so keep your own record of whose each object ID was for the whole retention period.
- **Time-stamp authorities:** the free default (FreeTSA, Sectigo and DigiCert, in three
  jurisdictions) or paid ones, and who signs the assessment (5.2, 7.2).
- **The approver:** the person who submits the genesis `config.changed` with their own sign-in.
  Their object ID is the gateway's bootstrap caller.
- **Callers:** each agent or application that writes entries, by object ID or app role, and the
  entry types each may write.
- **The image:** the digest of a release, such as
  `ghcr.io/attunesolutions/sheaf@sha256:<digest>`. The mandate records it as `gateway.image`.
  Never deploy a tag; a tag can move, a digest cannot.

## 3 Network

```bash
az group create -n <rg> -l <region>
az network vnet create -g <rg> -n <vnet> --address-prefixes 10.40.0.0/24
az network vnet subnet create -g <rg> --vnet-name <vnet> -n apps \
  --address-prefixes 10.40.0.0/27 --delegations Microsoft.App/environments
az network vnet subnet create -g <rg> --vnet-name <vnet> -n endpoints \
  --address-prefixes 10.40.0.64/27
for zone in privatelink.blob.core.windows.net privatelink.vaultcore.azure.net; do
  az network private-dns zone create -g <rg> -n $zone
  az network private-dns link vnet create -g <rg> -z $zone -n <vnet> -v <vnet> -e false
done
```

Outbound, the witness job needs HTTPS (and HTTP for DigiCert) to the authorities in the mandate,
and both workloads need Entra ID and the image registry. If outbound traffic goes through a
firewall, allow: `login.microsoftonline.com`, `ghcr.io` and `pkg-containers.githubusercontent.com`,
`freetsa.org`, `timestamp.sectigo.com`, `timestamp.digicert.com`.

## 4 Storage

```bash
az storage account create -g <rg> -n <account> -l <region> --kind StorageV2 --sku Standard_ZRS \
  --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false \
  --public-network-access Disabled
az storage account blob-service-properties update -g <rg> -n <account> --enable-versioning true
az storage container-rm create -g <rg> --storage-account <account> -n evidence --enable-vlw true
az storage container-rm create -g <rg> --storage-account <account> -n gateway-state
```

Use `Standard_LRS` where the region has no zones. With public access disabled, run the data-plane
steps from inside the network, or allow your own address for the duration.

**The container's default policy** is the floor under every blob (4). Set it to the shortest
retention class, in days, and leave it **unlocked** until section 10:

```bash
az storage container immutability-policy create -g <rg> --account-name <account> -c evidence \
  --period 365
```

**Tiering:** a lifecycle rule moves blobs to Cold after about 90 days (4). Moving tier is allowed
under immutability.

```json
{ "rules": [ { "name": "cold-after-90-days", "enabled": true, "type": "Lifecycle",
  "definition": {
    "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["evidence/"] },
    "actions": { "baseBlob": { "tierToCold": { "daysAfterCreationGreaterThan": 90 } } } } } ] }
```

```bash
az storage account management-policy create -g <rg> --account-name <account> --policy @policy.json
```

**Private endpoint** for Blob, registered in the private DNS zone:

```bash
az network private-endpoint create -g <rg> -n <account>-blob --vnet-name <vnet> --subnet endpoints \
  --private-connection-resource-id $(az storage account show -g <rg> -n <account> --query id -o tsv) \
  --group-id blob --connection-name blob
az network private-endpoint dns-zone-group create -g <rg> --endpoint-name <account>-blob \
  -n default --private-dns-zone privatelink.blob.core.windows.net --zone-name blob
```

## 5 Key Vault and the witness key

```bash
az keyvault create -g <rg> -n <vault> -l <region> --enable-rbac-authorization true \
  --enable-purge-protection true --public-network-access Disabled
az keyvault key create --vault-name <vault> -n acme-witness --kty EC --curve P-256 --ops sign verify
```

Create the key with no release policy and without `--exportable`, so it can never leave the vault
(7.5). Its id for the mandate is `<name>/<version>`, for example `acme-witness/<version>`. Add a
private endpoint as for Blob (`--group-id vault`, zone `privatelink.vaultcore.azure.net`), and a
diagnostic setting that sends `AuditEvent` logs to the workspace, so every signature is on record.

Purge protection is on: a production vault must not be purgeable. Test vaults should leave it off.

## 6 Identities and roles

```bash
az identity create -g <rg> -n acme-sheaf-gateway
az identity create -g <rg> -n acme-sheaf-witness
```

No built-in role fits the gateway, which may create and read evidence but never delete it (7.5),
nor the witness, which may sign and nothing else. Define two custom roles:

```json
{ "Name": "Sheaf evidence writer", "IsCustom": true,
  "Description": "Create and read blobs and their tags. No delete.",
  "Actions": [], "NotActions": [],
  "DataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write" ],
  "NotDataActions": [], "AssignableScopes": ["/subscriptions/<subscription>"] }
```

```json
{ "Name": "Sheaf witness signer", "IsCustom": true,
  "Description": "Read the witness key's public part and sign with it. Nothing else.",
  "Actions": [], "NotActions": [],
  "DataActions": [
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.KeyVault/vaults/keys/sign/action" ],
  "NotDataActions": [], "AssignableScopes": ["/subscriptions/<subscription>"] }
```

Whether setting a blob's own retention needs a further data action is one of the checks in section
9: prove it with the gateway's identity, not your own.

| Identity | Role | Scope |
|---|---|---|
| Gateway | Sheaf evidence writer | The `evidence` container |
| Gateway | Storage Blob Data Contributor | The `gateway-state` container |
| Witness | Storage Blob Data Reader | The `evidence` container |
| Witness | Sheaf witness signer | The witness key |

A container scope is
`<account id>/blobServices/default/containers/<name>`; a key scope is `<vault id>/keys/<name>`.
Under pseudonymised identifiers the gateway also needs to read and create secrets in a vault, and
to delete none (5.7).

## 7 The gateway's API in Entra ID

Register one application for the gateway's API, single tenant:

- **Access tokens v2:** set `api.requestedAccessTokenVersion` to `2`, so tokens carry the v2
  issuer the gateway checks.
- **Identifier URI:** `api://<application id>`.
- **App roles:** one for each role in the mandate's `policy.roles`, plus one for the witness
  (for example `witness`), allowed for applications or users as each role needs.
- **A delegated scope** (for example `user_impersonation`) for applications that act for a
  person, who then submits with their own sign-in (5.1).
- **Assignment required** on its service principal, then assign each caller its app role: agents
  and applications by service principal, people through groups, and the witness's identity the
  `witness` role. An unassigned identity then cannot get a token for the gateway at all.

The gateway's `SHEAF_ENTRA_TENANT` is the directory (tenant) ID and `SHEAF_ENTRA_AUDIENCE` is the
application (client) ID. The witness asks for `api://<application id>/.default`.

## 8 Container Apps

```bash
az containerapp env create -g <rg> -n <environment> -l <region> \
  --enable-workload-profiles --infrastructure-subnet-resource-id <apps subnet id> \
  --internal-only true --logs-workspace-id <workspace id> --logs-workspace-key <workspace key>
```

An internal environment has a private address and its own default domain. Callers elsewhere in the
network resolve it through a private DNS zone for that domain, with a wildcard record pointing at
the environment's static IP (`az containerapp env show --query properties.staticIp`).

**The gateway**, one app per workflow, exactly one replica:

```bash
az containerapp create -g <rg> -n acme-case-review-gateway --environment <environment> \
  --image ghcr.io/attunesolutions/sheaf@sha256:<digest> \
  --user-assigned <gateway identity id> \
  --ingress internal --target-port 8080 --min-replicas 1 --max-replicas 1 \
  --env-vars SHEAF_STORE=azure SHEAF_STORAGE_URL=https://<account>.blob.core.windows.net \
    SHEAF_IMMUTABILITY=Unlocked SHEAF_CHAIN=acme/case-review \
    SHEAF_IDENTIFIERS=clear SHEAF_BOOTSTRAP_CALLER=<approver object id> \
    SHEAF_ENTRA_TENANT=<tenant id> SHEAF_ENTRA_AUDIENCE=<application id> \
    AZURE_CLIENT_ID=<gateway identity client id>
```

`SHEAF_IMMUTABILITY` becomes `Locked` in section 10. Under pseudonymised identifiers add
`SHEAF_KEY_VAULT_URL`. On every start the gateway takes the chain-head lease, rebuilds its state
from the container and finishes any half-written entry from its journal before it accepts a call.

`<gateway fqdn>` is the gateway's internal address:
`az containerapp show -g <rg> -n acme-case-review-gateway --query properties.configuration.ingress.fqdn`.

**The witness**, daily shortly after midnight UTC, with time for the authorities' retries
(six hours, 7.2):

```bash
az containerapp job create -g <rg> -n acme-case-review-witness --environment <environment> \
  --trigger-type Schedule --cron-expression "10 0 * * *" \
  --replica-timeout 25200 --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1 \
  --image ghcr.io/attunesolutions/sheaf@sha256:<digest> \
  --mi-user-assigned <witness identity id> \
  --command "python" --args "-m" "sheaf_witness" \
  --env-vars SHEAF_CHAIN=acme/case-review \
    SHEAF_GATEWAY_URL=https://<gateway fqdn> \
    SHEAF_GATEWAY_SCOPE=api://<application id>/.default \
    SHEAF_CONTAINER_URL=https://<account>.blob.core.windows.net/evidence \
    SHEAF_KEY_VAULT_URL=https://<vault>.vault.azure.net \
    SHEAF_WITNESS_IDENTITY=<witness identity object id> \
    AZURE_CLIENT_ID=<witness identity client id>
```

A mandate change applies only once it has its interim witness (7.2), so after each
`config.changed` start the job by hand rather than waiting for midnight:

```bash
az containerapp job start -g <rg> -n acme-case-review-witness
```

## 9 Check before you lock

Run the checks of the standard's section 11 in this region, with every policy still unlocked, and
against a scratch container (`evidence-check`, with the same settings) so the real container holds
nothing before its genesis entry. Run them as the workloads' identities, not your own:

1. The gateway's identity writes a blob, sets and extends its retention, and is refused a delete.
2. A 100 MiB artefact, the largest kind allows (6), uploads through the internal ingress.
3. Index tags change on an immutable blob; a blob moves to Cold.
4. The witness's identity signs with the key, a signature verifies with `sheaf_core`, and every
   other key operation is refused. The key cannot be exported.
5. The Key Vault audit log shows each signature, in a workspace the gateway cannot write.
6. The witness job reaches every authority in the mandate, and their tokens verify against the
   roots the mandate pins.
7. Stop the gateway mid-write and start it again: it finishes the entry from its journal.

Delete the scratch container when done.

## 10 Lock

**Locking cannot be undone.** A locked policy can be extended but never shortened or removed, and
the storage account cannot be deleted until every blob in it has expired. Check the period first.

```bash
etag=$(az storage container immutability-policy show -g <rg> --account-name <account> \
  -c evidence --query etag -o tsv)
az storage container immutability-policy lock -g <rg> --account-name <account> -c evidence \
  --if-match "$etag"
az containerapp update -g <rg> -n acme-case-review-gateway \
  --set-env-vars SHEAF_IMMUTABILITY=Locked
```

From now on the gateway sets every blob's own retention as `Locked`. Put a `CanNotDelete` lock on
the resource group too, so nobody removes the network or the vault from under the record.

## 11 Genesis

The first entry is the genesis `config.changed` (5.6): the approver's own sign-in, the mandate and
everything it names.

1. **Write the mandate** (`sheaf.mandate/1`): the chain, policy (callers and roles), instructions,
   tenant schemas, retention classes, witness interval, `witness_key` (the key id,
   `ES256`, the SHA-256 of its public key in PEM form, and the witness identity's object ID),
   authorities and their assessment, `personal_data`, and `gateway.image` (the digest deployed in
   section 8).
2. **Upload** the mandate, its instructions and its schemas: `PUT /v1/artefacts/{sha256}`.
3. **Store the trust files** the mandate names, the witness key's PEM and each authority's root:
   `PUT /v1/trust/{path}`.
4. **Commit the `config.changed`** with `POST /v1/entries`, signed in as the approver.
5. **Start the witness job.** Its interim witness puts the mandate in force; until then the gateway
   accepts nothing else.

## 12 Running it

- **A new image** is a mandate change: commit a `config.changed` naming the new digest as
  `gateway.image`, let it be witnessed, then update the gateway app and the witness job to that
  digest.
- **Rotating the witness key** is also a `config.changed`: create a new key version, store its
  public key under `trust/witness-keys/`, and name it in the new mandate.
- **A halted gateway** answers `503` after a write failed partway or its lease was lost. Restart
  the revision; it finishes the entry from its journal and carries on.
- **Watch for:** `503` answers, witness job failures, a day without a daily witness, and Key Vault
  signatures that do not match the witness job's runs.
- **Never** unlock, shorten or delete anything in the `evidence` container. Deletion after expiry
  is a separate, logged step preceded by a `retention.expired` entry (5.7).

## 13 Not built yet

As of `v0.1.0`:

- **Genesis tooling:** no command builds a mandate, uploads it with its trust files and commits
  the `config.changed`; section 11 is done against the API by hand.
- **The verifier** (9).
- **Events to readers** (7.2 step 4): the gateway publishes none yet.
- **Idempotency receipts** are kept in memory, so a caller's retry that arrives after a gateway
  restart is not recognised and can commit the same entry a second time. Callers should check the
  record before retrying across a restart.
- **Optional parts:** malware scanning (7.4), interim witnesses after `dossier.sealed`, and
  revocation data for tokens.
