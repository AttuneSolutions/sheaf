# Deploying Sheaf

How to deploy Sheaf for one tenant in its own Azure subscription: the storage, the witness key, the
identities, the gateway, the witness job, the approval page, the checks before anything is locked,
and the first entry. Sections of [the standard](standard.md) are cited by number.

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
| Gateway app | One for the tenant, serving every workflow's chain, one replica (7.1) |
| Witness job | One scheduled job for every chain, from the same image, with its own identity (7.5) |
| Approval service | `sheaf-approve`, from the same image: where an approver approves a mandate change in their own browser (7.6). It has no identity of its own |
| Two Entra ID app registrations | The gateway's API (the audience callers ask for tokens to, and its app roles), and the approval page's sign-in |
| Two managed identities | The gateway's and the witness's, never shared |

There is no reverse proxy in front of the gateway. The environment's built-in ingress terminates
TLS and, set to internal, admits only callers inside the virtual network. A second proxy would be
one more thing that sees every artefact and every caller's token. If a caller must reach the
gateway from outside the network, put an Azure-managed front door in front of it (Application
Gateway with WAF, or Front Door Premium over Private Link) rather than a proxy you run yourself.

The approval page is the one thing people reach from outside the network: an approver uses their
own browser on their own device, where the tenant's Conditional Access is satisfied, and the page
relays their token to the gateway from inside. It is published through the tenant's reverse proxy
(section 8); the gateway stays internal.

## 2 Decide first

These go into the genesis mandate (5.6). Some cannot change once the tenant has written its first
entry; the rest change only through a `config.changed`.

- **Region:** where the record lives. Everything below is created there.
- **Workflows:** each workflow is one chain (`acme/case-review`), with its own mandate. One
  gateway and one witness job serve them all.
- **Retention classes:** for example `regulated-record` for `P7Y` and `working-file` for `P1Y`.
  The longest class sets how long chain-level blobs are kept (4).
- **Identifiers:** `clear` or `pseudonymised` (5.7). In clear, people are recorded by their Entra
  object ID, so keep your own record of whose each object ID was for the whole retention period.
- **Time-stamp authorities:** the free default (FreeTSA, Sectigo and DigiCert, in three
  jurisdictions) or paid ones, and who signs the assessment (5.2, 7.2).
- **Who proposes and who approves** (7.6): proposers stage mandate changes; an approver, usually
  the workflow's policy owner, approves each one with their own sign-in. The genesis approver's
  object ID is the gateway's bootstrap caller. Decide whether one person may do both
  (`policy.four_eyes`): `true` is recommended, and needed wherever an operator account is also in
  the approver group for routine changes. Under it, the genesis is proposed by someone other
  than the bootstrap caller.
- **How approvers reach the approval page:** the tenant's reverse proxy, and the address it
  publishes (section 8).
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

**An existing network** serves as well: add the two subnets to it, and create the zones once,
beside its other private DNS zones (only one zone of each name can be linked to a network). If the
network uses its own DNS servers, they must forward `blob.core.windows.net` and
`vaultcore.azure.net` to Azure DNS (`168.63.129.16`). Keep Sheaf's resources in a group of their
own all the same: the storage account cannot be deleted while any blob is under retention, and
section 10 locks the group. A NAT gateway on the apps subnet gives the witness a fixed outbound
address.

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

**Lifecycle rules:**

- Blobs in `evidence` move to Cold after about 90 days (4). Moving tier is allowed under
  immutability.
- The gateway's receipts for idempotency keys, in `gateway-state/receipts/`, are deleted after 30
  days, the least the standard promises callers (7.2).
- Proposals, in `gateway-state/proposals/`, are deleted 180 days after they last changed: long
  after any could still be pending (at most 90 days), and the record keeps every approval.
- Earlier versions in `gateway-state` are deleted after a week. Versioning is on for the whole
  account, so every journal write leaves one behind.

```json
{ "rules": [
  { "name": "cold-after-90-days", "enabled": true, "type": "Lifecycle",
    "definition": {
      "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["evidence/"] },
      "actions": { "baseBlob": { "tierToCold": { "daysAfterCreationGreaterThan": 90 } } } } },
  { "name": "receipts-after-30-days", "enabled": true, "type": "Lifecycle",
    "definition": {
      "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["gateway-state/receipts/"] },
      "actions": { "baseBlob": { "delete": { "daysAfterModificationGreaterThan": 30 } } } } },
  { "name": "proposals-after-180-days", "enabled": true, "type": "Lifecycle",
    "definition": {
      "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["gateway-state/proposals/"] },
      "actions": { "baseBlob": { "delete": { "daysAfterModificationGreaterThan": 180 } } } } },
  { "name": "gateway-state-versions-after-7-days", "enabled": true, "type": "Lifecycle",
    "definition": {
      "filters": { "blobTypes": ["blockBlob"], "prefixMatch": ["gateway-state/"] },
      "actions": { "version": { "delete": { "daysAfterCreationGreaterThan": 7 } } } } } ] }
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
az keyvault create -g <rg> -n <vault> -l <region> --sku premium --enable-rbac-authorization true \
  --enable-purge-protection true --public-network-access Disabled
az keyvault key create --vault-name <vault> -n acme-witness --kty EC-HSM --curve P-256 \
  --ops sign verify
```

Create the key with no release policy and without `--exportable`, so it can never leave the vault
(7.5). `EC-HSM` keeps it in a hardware security module, which needs the Premium tier; Premium has
no base charge, but an HSM-backed EC key is billed monthly (US$5 at list price). A software key
(`--kty EC`, any tier) is billed only per operation, and cannot be exported either. Its id for the mandate is `<name>/<version>`, for example `acme-witness/<version>`. Add a
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
  "Description": "Create new blobs, read them, set their tags and retention. No overwrite, no delete.",
  "Actions": [], "NotActions": [],
  "DataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/immutableStorage/runAsSuperUser/action" ],
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

`add/action` creates a blob but cannot write over one; `blobs/write`, which can, is left out. Under
version-level immutability an overwrite does not change a protected version, but it would put a
new current version on top of it. Without it, Azure refuses any upload to an existing blob with
`403 UnauthorizedBlobOverwrite`, which the gateway reads as "already stored". Setting a blob's own
retention needs `immutableStorage/runAsSuperUser/action`, which also lets an unlocked policy be
removed; once section 10 locks it, nobody can remove or shorten it.

A proposer compares the witness key file in a new mandate with the key the vault holds, before
staging it (section 11), and needs to read the public key and nothing more:

```json
{ "Name": "Sheaf witness key reader", "IsCustom": true,
  "Description": "Read the witness key's public part. No signing.",
  "Actions": [], "NotActions": [],
  "DataActions": [ "Microsoft.KeyVault/vaults/keys/read" ],
  "NotDataActions": [], "AssignableScopes": ["/subscriptions/<subscription>"] }
```

| Identity | Role | Scope |
|---|---|---|
| Gateway | Sheaf evidence writer | The `evidence` container |
| Gateway | Storage Blob Data Contributor | The `gateway-state` container |
| Witness | Storage Blob Data Reader | The `evidence` container |
| Witness | Sheaf witness signer | The witness key |
| Proposers (a group, or a proposer's managed identity) | Sheaf witness key reader | The witness key |

The approval service has no identity and no role: it acts only with the approver's own token.
Nobody who approves needs, or should have, write access to the witness job or any identity able
to sign with the witness key.

A container scope is
`<account id>/blobServices/default/containers/<name>`; a key scope is `<vault id>/keys/<name>`.
Under pseudonymised identifiers the gateway also needs to read and create secrets in a vault, and
to delete none (5.7).

## 7 Entra ID: the gateway's API and the approval page

**The gateway's API.** One application, single tenant, API only:

- **Access tokens v2:** set `api.requestedAccessTokenVersion` to `2`, so tokens carry the v2
  issuer the gateway checks.
- **Identifier URI:** `api://<application id>`.
- **A delegated scope**, `user_impersonation`, for anything that acts for a person, who then
  submits with their own sign-in (5.1).
- **Authorised clients** of that scope (*Expose an API*, *Add a client application*): the
  approval page's application below, and the Azure CLI
  (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) for people who run `sheaf-admin` from inside the
  network.
- **App roles**, each assigned through a group or to a service principal:

  | Value | Who | May |
  |---|---|---|
  | each role in the mandate's `policy.roles`, for example `approver` and `reviewer` | People | The entry types the mandate grants that role, such as `config.changed` |
  | `proposer` | Engineers and operators; a release pipeline's or a staging host's identity | Stage and withdraw mandate changes, upload their parts and trust files, read proposals (7.6) |
  | `status` | Operators, the tenant's operations staff, a reader | `GET /v1/status` and nothing else (7.7). Proposers and approvers may read status too |
  | `witness` | The witness's identity | Submit witnesses |
  | one for each agent's role, if the mandate grants by role | Applications | As the mandate says |

  Allow each for users or applications as it needs. Name a role by the value the mandate uses:
  the gateway reads the `roles` claim, never a group's name.

  Give `proposer` only to people and identities you trust with the record. A proposer cannot
  change what applies without an approver, but what it uploads stays: mandate parts it never
  proposes are kept for the container's minimum retention, and the first witness key stored
  under a key ID is the only one that key ID can ever name (a new key version is the way round
  a wrong one). A proposer can also stage a mandate someone else uploaded; an approver can
  withdraw it.
- **Assignment required** on its service principal, so an identity with no role cannot get a
  token for the gateway at all.

The gateway's `SHEAF_ENTRA_TENANT` is the directory (tenant) ID and `SHEAF_ENTRA_AUDIENCE` is the
application (client) ID. The witness asks for `api://<application id>/.default`.

**The approval page.** A second application, `acme-sheaf-approve`, single tenant:

- **Platform:** single-page application, with one redirect URI: the page's published address
  exactly, such as `https://approve.acme.example/` (section 8). No secret, no certificate.
- **API permissions:** the gateway's `user_impersonation` (delegated), already consented because
  the gateway authorises this client.
- **Assignment required** on its service principal, and assign the groups of the people who
  approve, propose or read status. Nobody else can sign in to the page.

Its application ID is the service's `SHEAF_APPROVE_CLIENT_ID`. The page signs in with the
authorisation code flow and PKCE, entirely in the browser, and asks for the code in the address's
fragment, which a browser never sends to a server.

## 8 Container Apps

```bash
az containerapp env create -g <rg> -n <environment> -l <region> \
  --enable-workload-profiles --infrastructure-subnet-resource-id <apps subnet id> \
  --internal-only true --logs-workspace-id <workspace id> --logs-workspace-key <workspace key>
```

An internal environment has a private address and its own default domain. Callers elsewhere in the
network resolve it through a private DNS zone for that domain, with a wildcard record pointing at
the environment's static IP (`az containerapp env show --query properties.staticIp`).

**The gateway**, one app for the tenant, exactly one replica:

```bash
az containerapp create -g <rg> -n acme-sheaf-gateway --environment <environment> \
  --image ghcr.io/attunesolutions/sheaf@sha256:<digest> \
  --user-assigned <gateway identity id> \
  --ingress external --target-port 8080 --min-replicas 1 --max-replicas 1 \
  --env-vars SHEAF_STORE=azure SHEAF_STORAGE_URL=https://<account>.blob.core.windows.net \
    SHEAF_IMMUTABILITY=Unlocked SHEAF_CHAINS=acme/case-review,acme/claims-triage \
    SHEAF_IDENTIFIERS=clear SHEAF_BOOTSTRAP_CALLER=<approver object id> \
    SHEAF_ENTRA_TENANT=<tenant id> SHEAF_ENTRA_AUDIENCE=<application id> \
    AZURE_CLIENT_ID=<gateway identity client id>
```

`--ingress external` admits the virtual network: the environment is internal, so it has no public
address at all. `internal` would admit only other apps in the same environment.
`--min-replicas 0` suits a gateway with little traffic: it then costs nothing while idle, starts
on the first request, and rebuilds each chain from the container before it serves it, which takes
longer as the chain grows. Never more than one replica.

`SHEAF_IMMUTABILITY` becomes `Locked` in section 10. Under pseudonymised identifiers add
`SHEAF_KEY_VAULT_URL`. On every start the gateway answers at once and, in the background, takes
each chain's lease, rebuilds its state from the container and finishes any half-written entry from
its journal. Until a chain has started, a request for it waits up to 30 seconds and is then
refused with `503 gateway_starting` and a `Retry-After`; the witness job keeps asking for up to
ten minutes. A chain whose stored record does not add up is halted, and the others carry on.

A restart or an update starts the new replica beside the old one and moves traffic to it before
stopping the old one. The new one cannot take a chain's lease until the old one stops; the old one
releases its leases as it stops (if it is killed first, at the end of
`--termination-grace-period`, the new one waits about a minute for them to expire). The new one
then rebuilds each chain before serving it, so writes pause for as long as that takes: it reads
every entry, several at a time, and grows with the chain. The gateway logs how long each chain took
to start (`acme/case-review started at seq <seq> in <seconds>s`).

`<gateway fqdn>` is the gateway's internal address:
`az containerapp show -g <rg> -n acme-sheaf-gateway --query properties.configuration.ingress.fqdn`.

**The witness**, daily shortly after midnight UTC, with time for the authorities' retries
(six hours, 7.2):

```bash
az containerapp job create -g <rg> -n acme-sheaf-witness --environment <environment> \
  --trigger-type Schedule --cron-expression "10 0 * * *" \
  --replica-timeout 25200 --replica-retry-limit 0 --parallelism 1 --replica-completion-count 1 \
  --image ghcr.io/attunesolutions/sheaf@sha256:<digest> \
  --mi-user-assigned <witness identity id> \
  --command "sheaf-witness" \
  --env-vars SHEAF_CHAINS=acme/case-review,acme/claims-triage \
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
az containerapp job start -g <rg> -n acme-sheaf-witness
```

**The approval service**, from the same image, with no identity of its own:

```bash
az containerapp create -g <rg> -n acme-sheaf-approve --environment <environment> \
  --image ghcr.io/attunesolutions/sheaf@sha256:<digest> \
  --ingress external --target-port 8080 --min-replicas 1 --max-replicas 2 \
  --command "sheaf-approve" \
  --env-vars SHEAF_CHAINS=acme/case-review,acme/claims-triage \
    SHEAF_GATEWAY_URL=https://<gateway fqdn> \
    SHEAF_GATEWAY_SCOPE=api://<gateway application id>/user_impersonation \
    SHEAF_ENTRA_TENANT=<tenant id> \
    SHEAF_APPROVE_CLIENT_ID=<approval page application id> \
    SHEAF_APPROVE_URL=https://approve.acme.example/
```

It keeps nothing, so any replica serves any request. It is always running; who can reach it is
decided at the proxy, not by starting and stopping it. `SHEAF_APPROVE_URL` is the address people
use, the same as the redirect URI in section 7. It logs each request's method and path, and each
approval attempt (who, which proposal, the outcome), never a token or a sign-in code.

**Publishing it.** Approvers reach the page from their own devices, so publish its internal
address through the tenant's reverse proxy, one of:

- **Pangolin**, with Newt on a host in the network that reaches the service, and Entra ID as
  Pangolin's identity provider, so the approver signs in once.
- **Entra Application Proxy**, which pre-authenticates with Entra ID, applies Conditional Access,
  and needs no inbound port; its connector runs on a host in the network.
- **Application Gateway with WAF**, or **Front Door Premium over Private Link**.

Whichever: HTTPS only, the address in `SHEAF_APPROVE_URL`, rate limits and country rules at the
proxy, and only the approval service behind it, never the gateway.

## 9 Check before you lock

Run the checks of the standard's section 11 in this region, with every policy still unlocked, and
against a scratch container (`evidence-check`, with the same settings) so the real container holds
nothing before its genesis entry. Run them as the workloads' identities, not your own:

1. The gateway's identity creates a blob, sets and extends its retention, and is refused a delete
   and an overwrite (`403 UnauthorizedBlobOverwrite`), even of a blob with no retention of its
   own.
2. The largest artefact a kind allows (6) uploads through the internal ingress, and one byte
   more is refused with `413`. Of the kinds whose validators are built, that is
   `ai.exchange.raw` at 50 MiB (section 13).
3. Index tags change on an immutable blob; a blob moves to Cold.
4. The witness's identity signs with the key, a signature verifies with `sheaf_core`, and every
   other key operation is refused. The key cannot be exported.
5. The Key Vault audit log shows each signature, in a workspace the gateway cannot write.
6. The witness job reaches every authority in the mandate, and their tokens verify against the
   roots the mandate pins.
7. Under load, restart the gateway (`az containerapp revision restart`) and update it (a new
   revision): no `seq` is skipped or repeated, every refused request is a `503 gateway_starting`
   that succeeds when retried, and writes pause for about as long as the gateway logs it took to
   start. Note that time: with `--min-replicas 0` the first request after an idle spell waits for
   it too. Container Apps moves traffic away from a replica before stopping it, so this does not
   stop the gateway mid-write; finishing an entry from the journal after a crash is covered by
   the tests and was confirmed on Blob (the standard's section 11).

8. Through the proxy, from outside the network: the approval page loads and signs in; `/api/me`
   without a token is `401`; a person without the approver role sees a proposal and its
   fingerprint, but approving it is refused and the chain's head in `GET /v1/status` does not
   move; and the service's log (`ContainerAppConsoleLogs_CL` for `acme-sheaf-approve`) holds no
   token (search for `eyJ`, the start of every one) and no `code=`.
9. `GET /v1/status` answers a token holding the `status` role and refuses one holding no role.
   It reports the immutability mode the gateway was deployed with; the container's own policy
   and its period are read with
   `az storage container immutability-policy show`, which the gateway's role cannot do.

Delete the scratch container when done.

## 10 Lock

**Locking cannot be undone.** A locked policy can be extended but never shortened or removed, and
the storage account cannot be deleted until every blob in it has expired. Check the period first.

```bash
etag=$(az storage container immutability-policy show -g <rg> --account-name <account> \
  -c evidence --query etag -o tsv)
az storage container immutability-policy lock -g <rg> --account-name <account> -c evidence \
  --if-match "$etag"
az containerapp update -g <rg> -n acme-sheaf-gateway \
  --set-env-vars SHEAF_IMMUTABILITY=Locked
```

From now on the gateway sets every blob's own retention as `Locked`. Put a `CanNotDelete` lock on
the resource group too, so nobody removes the network or the vault from under the record.

## 11 Genesis

Each chain's first entry is its genesis `config.changed` (5.6): the chain's mandate and
everything it names. It is made like every later mandate change (7.6): a proposer stages it, and
the approver approves it with their own sign-in. `sheaf-admin` builds the mandate from files,
checks it offline with the rules the gateway runs, and stages it; the approver approves it in the
approval page (section 8), or with `sheaf-admin approve` from inside the network. Do this once for
each chain in `SHEAF_CHAINS`.

A genesis cannot be taken back. The container is locked, so a mistake stays in the record for the
retention period, and a mandate that cannot be witnessed never applies.

1. **Find your identity.** `sheaf-admin` runs from a machine that reaches the gateway's internal
   address, with a checkout of the release you deployed (`git checkout v<version> && uv sync`),
   or inside the image. It signs in through the Azure CLI (`az login` as yourself), or, where
   Conditional Access refuses the CLI, as a managed identity on a host or job in the network
   holding the `proposer` role and the Sheaf witness key reader role (`--credential managed`,
   with `AZURE_CLIENT_ID`):

   ```bash
   uv run sheaf-admin whoami --gateway https://<gateway fqdn> \
     --scope api://<application id>/.default
   ```

   `id` is how entries name you: under clear identifiers your object ID; under pseudonymised
   ones your pseudonym. The approver's own `id` is the gateway's `SHEAF_BOOTSTRAP_CALLER` (as an
   object ID); they can see it on the approval page once signed in.

2. **Write the genesis file**, one folder per chain, beside the files it names:

   ```text
   genesis/case-review/
     genesis.json
     instructions/review.md
     schemas/findings.json
     witness.pem
   ```

   `witness.pem` is the public half of the witness key from section 5:

   ```bash
   az keyvault key download --vault-name <vault> --name acme-witness --version <version> \
     --encoding PEM --file genesis/case-review/witness.pem
   ```

   `genesis.json` is the mandate (`sheaf.mandate/1`, standard 5.6) as you mean it, except that
   where the mandate gives a file's SHA-256 you name the file, and the tool computes the digest
   from the bytes it uploads. Authorities are named from the witness's catalogue (the free
   default is `freetsa`, `sectigo` and `digicert`), or written out with `roots` as the paths of
   their DER certificates. Nobody is named as approver: whoever approves it is.

   ```json
   {
     "mandate": {
       "$schema": "sheaf.mandate/1",
       "chain": "acme/case-review",
       "version": "2026.11.1",
       "policy": {
         "callers": [
           {"id": "<agent object id>", "types": ["dossier.opened", "source.read", "ai.exchange",
             "trace.recorded", "finding.drafted", "output.produced", "correction", "notice",
             "dossier.sealed"]}
         ],
         "roles": [
           {"role": "reviewer", "types": ["decision.recorded"]},
           {"role": "approver", "types": ["config.changed", "retention.expired"]}
         ],
         "kinds": {
           "ai.exchange.raw": {"max_bytes": 20971520},
           "data.json": {"max_bytes": 5242880},
           "text.markdown": {"max_bytes": 1048576},
           "trace.otel": {"max_bytes": 20971520}
         },
         "source_capture": "reference",
         "sensitivity": {
           "client_pii": ["reviewer"],
           "staff_pii": ["approver"],
           "none": ["reviewer", "approver"]
         },
         "four_eyes": true
       },
       "instructions": [{"name": "review-instructions", "file": "instructions/review.md"}],
       "schemas": [{"id": "acme.findings/1", "file": "schemas/findings.json"}],
       "models": [
         {"provider": "azure-ai-foundry", "region": "<region>", "deployment": "case-review",
          "model": "<model>", "model_version": "<model version>",
          "parameters": {"temperature": "0.2"}}
       ],
       "registry": {"version": "1.0.0"},
       "retention": {"classes": [{"class": "regulated-record", "period": "P7Y"}]},
       "witness_interval": {"interval": "daily", "interim_after_sealed": false},
       "witness_key": {
         "key_id": "acme-witness/<version>",
         "algorithm": "ES256",
         "public_key": "witness.pem",
         "identity": "<witness identity object id>"
       },
       "authorities": {
         "list": ["freetsa", "sectigo", "digicert"],
         "assessment": {
           "by": {"kind": "person", "id": "<the assessor's id, as whoami shows it>"},
           "date": "2026-11-20",
           "statement": "<why no single order or treaty reaches every authority>"
         }
       },
       "personal_data": {"identifiers": "clear", "basis": "<the lawful basis>"},
       "gateway": {"image": "sha256:<digest deployed in section 8>"}
     }
   }
   ```

   Numbers are integers (5.2): a fraction, such as a model's temperature, is a string. The roles
   in `policy.roles` and `policy.sensitivity` are app role values from section 7, never group
   names. A `reason` beside `mandate` replaces the default, `genesis`.

3. **Check it offline**, and correct it until nothing is reported:

   ```bash
   uv run sheaf-admin check genesis/case-review/genesis.json
   ```

   The image you deployed holds the same tool, so the check can also run with exactly that code:

   ```bash
   docker run --rm -v "$PWD/genesis/case-review:/genesis:ro" \
     ghcr.io/attunesolutions/sheaf@sha256:<digest> sheaf-admin check /genesis/genesis.json
   ```

4. **Stage it**, as a proposer:

   ```bash
   uv run sheaf-admin propose genesis/case-review/genesis.json \
     --gateway https://<gateway fqdn> --scope api://<application id>/.default \
     --key-vault https://<vault>.vault.azure.net
   ```

   It checks again; makes sure `witness.pem` is the key the vault holds as `key_id`, since a
   mandate whose interim witness can never verify never applies; uploads the mandate, its
   instructions and its schemas; stores the trust files; and stages the proposal, which the
   gateway checks against the chain as it will check the genesis itself. It prints the mandate's
   fingerprint. If it stops partway, run it again: what is stored is kept, and the same bytes are
   accepted again. The proposal waits 14 days for its approver (`--expires-in-days` to change
   that).

5. **Approve it**, as the approver: open the approval page, sign in, and read what it shows: the
   mandate in plain language, and its fingerprint, which should be the one `propose` printed.
   Two things only a person can check: the witness identity is the witness job's identity
   (section 6), or every witness is refused; and the gateway image is the digest running. Type
   the chain name and approve. From a terminal inside the network,
   `sheaf-admin approve <fingerprint>` shows the same and does the same.

   Under four eyes the person who staged it cannot approve it, and the page says so.

6. **Start the witness job** (section 8). Its interim witness puts the mandate in force, and its
   log says `acme/case-review: witness committed at seq 2`. Until then the gateway accepts
   nothing else on that chain.

## 12 Running it

- **A mandate change** is made as the genesis was (section 11, steps 2 to 6): write the new
  mandate's file, check it, stage it with `sheaf-admin propose`, approve it, start the witness
  job. `sheaf-admin proposals` lists what is waiting, and `sheaf-admin withdraw <fingerprint>`
  takes one back. One change waits for its witness at a time; a proposal staged before another
  change was committed is superseded, and is staged again against the new mandate.
- **A new image** is a mandate change naming the new digest as `gateway.image`: let it be
  witnessed, then update the gateway app, the witness job and the approval service to that
  digest.
- **A new workflow** is a new chain: add it to `SHEAF_CHAINS` on the gateway and the witness job,
  let the gateway restart, then give it its own genesis (section 11).
- **Rotating the witness key** is also a `config.changed`: create a new key version, store its
  public key under `trust/witness-keys/`, and name it in the new mandate.
- **A halted gateway** answers `503` after a write failed partway or its lease was lost. Restart
  the revision; it finishes the entry from its journal and carries on.
- **Watch for:** `503` answers, witness job failures, a day without a daily witness, and Key Vault
  signatures that do not match the witness job's runs. `GET /v1/status`, under the `status`
  role, shows a halted chain, an overdue daily witness, a change waiting for its witness and the
  refusals of the last day; alert on those.
- **Never** unlock, shorten or delete anything in the `evidence` container. Deletion after expiry
  is a separate, logged step preceded by a `retention.expired` entry (5.7).

## 13 Not built yet

- **The verifier** (9).
- **Events to readers** (7.2 step 4): the gateway publishes none yet.
- **Validators** for `document.pdf`, `document.office`, `document.rendition`, `image.raster` and
  `trace.otel`: an artefact of those kinds is refused with `422 validator_unavailable`.
- **Alerts** from status: `GET /v1/status` reports, but nothing alerts on it yet. Until then,
  alert in Log Analytics on the gateway's `halted` and witness job failures.
- **On the approval page:** staging (`sheaf-admin propose` stages), the reviewer's screen for
  `decision.recorded`, a status view, and more than one approver for a change.
- **Reading the record** through the gateway (entries, and artefacts by sensitivity against the
  viewer's roles, section 8).
- **Optional parts:** malware scanning (7.4), interim witnesses after `dossier.sealed`, and
  revocation data for tokens.
