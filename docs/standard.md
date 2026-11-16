# Sheaf evidence dossier standard, version 1, and the write gateway

**Status:** draft 0.2, 16 November 2026. Spec id `sheaf/1`. Nothing has been written under it yet,
so anything here may still change; after a tenant's first write, section 10 governs change.

## 0 Status and scope

A storage standard for evidence that an automated workflow produces, and the **write gateway** that
enforces it. It covers what is written, where, in what shape, who may write it, how a write is checked
before it is committed, how the record is witnessed, and the contract any reader (a case viewer, a
regulator, a new supplier) uses to read and verify it.

Sheaf is the standard, the gateway, the witness and the open verifier. It runs in the customer's own
Azure subscription. Readers are separate products, and the record must stand up without any of them:
nothing here depends on a reader.

Sections 1-10 are the standard. Section 11 lists Azure behaviours to confirm at build.

Draft 0.2 takes the useful parts of MIO-STD-01 v0.2: outside time on the witness from two
authorities in different jurisdictions (5.2, 5.5, 7.2), graded time claims (5.5), a witness signer
that is not the writer (7.5), recorded expiry (5.7), a mandate that can be rebuilt from the container
alone (5.6), and verifier output that says what a pass does not show (9).

### 0.1 Alignment with MIO-STD-01

MIO-STD-01 v0.2 is a single-author working draft, licensed CC BY 4.0, that calls itself not
submittable. This standard is **aligned with MIO-STD-01 v0.2 clauses 4.1-4.4, 4.6.4, 5.1-5.3,
5.6-5.8, 6.1-6.3, 6.5 and 8.4 (J. G. Stroh, CC BY 4.0)**. It does not claim conformance, and must
never be described as conforming. The licence requires credit and forbids implying that the author
endorses this standard.

| Clause | What it asks | Here | Status |
|---|---|---|---|
| 4.1 | Append-only; corrections are new events | `correction` entries; locked immutability (4, 5.3) | Yes |
| 4.2 | Each seal commits to every earlier record | `prev` and `seq` chain (5.2) | Yes |
| 4.3 | The signing capability is outside every write path | Witness identity signs; the gateway writes and cannot sign (7.5) | Yes |
| 4.4 | Content enters events only as a digest | Artefacts addressed by SHA-256 (5.1) | Yes |
| 4.6.1-4.6.3 | No personal data sealed; keyed pseudonyms; erasure by destroying the key | Staff and subject identifiers are sealed in clear, or as keyed pseudonyms, by the tenant's choice | Per tenant (5.7) |
| 4.6.4 | Erasure is itself recorded as a sealed event | `retention.expired` before any lifecycle deletion (5.7) | Adapted: records expiry, not key destruction |
| 5.1, 5.2 | At least two independent RFC 3161 authorities per sealed batch | Every witness stamped by two authorities (5.5, 7.2) | Yes |
| 5.3 | Distinct jurisdictions, not reachable by one compulsion instrument; jurisdiction recorded | Jurisdiction recorded per authority; the 5.3.2 assessment is a person's, recorded in the mandate, never asserted by the verifier | Yes |
| 5.4 | A published register of eligible authorities | No register exists. Each authority's practice statement and audit reference are kept in the mandate instead | Partly; revisit if a register appears |
| 5.6 | The batch interval is a recorded property | Witness interval recorded in the mandate (5.5, 5.6) | Yes |
| 5.7, 5.8 | Every time claim carries its grade; the interval is an evidentiary parameter | 5.5 | Yes |
| 6.1-6.3 | Mandate sealed and attested before the acts it governs; amendments are new records; mandate in force derivable from the substrate alone | `config.changed` carries the whole mandate as artefacts and is witnessed before it applies (5.6) | Yes |
| 6.5 | Disclose that the inventory sees identities, not agents | 5.6, 9 | Yes |
| 7, 8.1-8.3 | Seed-based unpredictable audit; recognition rate | Sampling adds nothing where a person reviews every output. Possible later for a tenant whose oversight samples | Out of scope for v1 |
| 8.4 | Say that conformance evidences, and does not prevent | 9 | Yes |

Also out of scope for v1: post-quantum signatures and blockchain anchoring.

**Where this goes further than MIO-STD-01 asks.** The gateway *enforces* the mandate at write time
(callers, entry types, kinds, sizes); MIO-STD-01 only requires it to be recorded. The record sits
in the customer's own subscription and only the customer's gateway can write to it. And the
mandate's content, not just a reference to it, is bound into the chain by digest.

## 1 The idea in one paragraph

Each unit of work produces a **dossier**: an ordered list of **entries** (what happened) that point to
**artefacts** (the evidence itself: PDFs, images, text, JSON, AI request and response bodies, traces).
Every artefact belongs to a registered **kind** that says what it may contain, how it is checked and how
a reader may display it. Nothing reaches storage except through a **write gateway** that validates the artefact
against its kind and the entry against its schema, assigns its place in a hash **chain**, and commits it
to locked (write-once) Blob storage in the customer's own Azure subscription. A daily **witness**,
signed by a key the gateway cannot use and time-stamped by two independent authorities in different
jurisdictions, anchors the chain outside anyone's single control. Readers read the storage, build
their own index, and render each artefact by its kind; they never write.

## 2 Principles

| Principle | Consequence |
|---|---|
| **The customer holds the record** | Storage account in the customer's subscription and region. The gateway runs there too, so evidence never leaves the customer's tenancy to be validated. A reader's index is a rebuildable copy, not the record |
| **One writer, and it validates** | Only the gateway's identity can write. Callers cannot write to storage directly, so no unvalidated or malformed evidence can exist |
| **Closed set of kinds** | A kind not in the registry is rejected. Every artefact a reader meets is one the registry describes |
| **Store exactly what was used** | The gateway validates and rejects; it never transforms. A cleaned-up copy is a separate, derived artefact that points to its original |
| **Tamper-evident and write-once** | Hash-chained entries, content-addressed artefacts, version-level immutability, a daily witness time-stamped by outside authorities |
| **The writer cannot sign, and the signer cannot write** | The gateway commits entries but cannot use the witness key. The witness identity signs but can only read storage and submit witnesses (7.5) |
| **Verifiable without us** | The standard, the kind registry snapshot, the authorities' certificates and an open verifier live in the customer's storage. Neither a reader nor the gateway's authors are needed to read or check the record |
| **Claim no more than the evidence shows** | Every time carries its grade (5.5). The verifier says what a pass does not show (9) |
| **Reference, don't copy, by policy** | Whether a source document is copied into the dossier or referenced by fingerprint is a per-tenant policy (section 5.4), because some customers' contracts promise no copies |

## 3 Concepts

| Term | Meaning | Example |
|---|---|---|
| Tenant | One customer, one storage account | `acme` |
| Workflow | One automated process within a tenant; owns one chain | `case-review` |
| Dossier | All evidence for one unit of work | One review run of one case |
| Subject | The real-world thing the dossier is about, in the source system | CRM case `C104233` |
| Entry | One event in a dossier, chained | "AI request sent", "decision recorded" |
| Artefact | One immutable piece of evidence, addressed by its SHA-256 | The prompt as sent; a findings JSON |
| Kind | A registered artefact type with schema, validator and renderer | `ai.exchange.raw`, `document.pdf` |
| Chain | The ordered sequence of all entries in a workflow | `acme/case-review` |
| Witness | The chain's last fingerprint at the end of each witness interval, signed by the witness identity, time-stamped by two outside authorities and copied outside the writer's control | Stamped daily; emailed to the tenant's nominated person; copies in the customer's container and with an outside holder |
| Witness interval | How often the chain is witnessed. Times within one interval rest on the gateway's clock (5.5) | One UTC day |
| Time-stamp authority | An RFC 3161 authority independent of the operator | Two, in distinct jurisdictions, named in the mandate (5.6) |
| Mandate | Everything that fixes what a workflow may do: gateway policy, instructions, model configuration (5.6) | Policy file, the review instructions, the model deployment |

## 4 Storage layout

One storage account per tenant, in the tenant's subscription and region. One container, `evidence`,
with version-level immutability enabled.

| Path | Blob type | Contents | Retention |
|---|---|---|---|
| `dossiers/{workflow}/{yyyy}/{mm}/{dossier_id}/{seq}.json` | Block blob, one per entry | The entry | The dossier's retention class |
| `dossiers/{workflow}/{yyyy}/_chain/{seq}.json` | Block blob, one per entry | Chain-level entries, which belong to no unit of work: `config.changed`, `witness.*`, `retention.expired`, and any `notice` that concerns no dossier | As chain |
| `artefacts/sha256/{h0-1}/{h2-3}/{sha256}` | Block blob, `Content-Type` set | The artefact's exact bytes, stored once however many entries refer to it | The longest retention of any entry referring to it (a dossier's class, or as chain for a chain-level entry such as `config.changed`); extended when a new entry refers to it |
| `chain/{workflow}/{yyyy}/{mm}/{dd}/{seq}.json` | Block blob, one per entry | The day's record of each entry committed: `seq`, `dossier`, `type`, `hash`. No content | As chain (holds only identifiers and fingerprints) |
| `witness/{workflow}/{yyyy}/{mm}/{dd}.json` | Block blob | The daily witness: last `seq` and `hash` of the day, the witness identity's signature, and the time attestation (5.5) | As chain |
| `witness/{workflow}/{yyyy}/{mm}/{dd}.{authority}.tsr` | Block blob, `application/timestamp-reply` | One authority's RFC 3161 time-stamp response over that witness, exact bytes | As chain |
| `witness/{workflow}/{yyyy}/{mm}/{dd}.{authority}.rev` | Block blob | Revocation status of the authority's certificate (CRL or OCSP response) fetched at stamping, so it can be checked offline later. Recommended | As chain |
| `witness/{workflow}/interim/{seq}.json`, `.{authority}.tsr`, `.{authority}.rev` | Block blobs | An interim witness for the entry at `seq` (5.5) | As chain |
| `trust/tsa/{authority}/` | Block blobs | The authority's root and intermediate certificates, jurisdiction and practice-statement reference, as at first use | As chain |
| `trust/witness-keys/{key_id}.pem` | Block blob | Each public key the witness has signed with | As chain |
| `registry/sheaf-1/{registry_version}/` | Block blobs | The kind registry and every JSON Schema in force for that version | As chain |
| `verifier/{version}/` | Block blobs | The open verifier, its instructions, and its pinned dependencies as wheels (9) | As chain |

Dates in paths and witness days are **UTC**, matching `committed_at`, so no day is 23 or 25 hours
long. A dossier's entries are filed under the month its `dossier.opened` was committed.
`{authority}` is a short identifier fixed in the mandate. `{seq}` is written with 16 digits,
zero-padded, so a listing of a folder comes back in `seq` order. A segment record is the RFC 8785
form of `{seq, dossier, type, hash}`, newline-terminated. Every blob is written once and never
appended to: under version-level immutability Azure refuses appends and sealing once any
retention policy applies. A dossier closes with its `dossier.sealed` entry, after which the
gateway accepts nothing more for it (5.3).

**Immutability.** Version-level, time-based retention, **locked** before go-live. The container's
default policy is the floor for every blob. The gateway sets each blob's own retention at write,
through the whole of its last day, and only ever extends it: a dossier's entries and the artefacts
they refer to by the dossier's class; everything kept "as chain" (chain-level entries and the
artefacts they refer to, segment records, witness files and the trust files a mandate names) by the
longest class in the mandate in force, counted from the day written. Deletion after expiry is a
separate, logged lifecycle step under the customer's retention specification, never automatic, and
always preceded by a `retention.expired` entry (5.7).

**Tiers.** Write Hot or Cool, then move to Cold after about 90 days with a lifecycle rule, so a
viewer's frequent reads of recent dossiers stay cheap.

**Index tags** (at most 10 per blob; values ≤256 characters). Tags are an index, not part of the
record, and the verifier ignores them.

| On | Tags |
|---|---|
| A dossier's `dossier.opened` entry blob | `tenant`, `workflow`, `dossier`, `subject_system`, `subject_id`, `subject_date`, `status` (`open`, `sealed`, `superseded`), `owner` (e.g. the case owner's identifier), `retain_until` |
| Artefact blobs | `kind`, `sensitivity` |

## 5 Entries

### 5.1 Envelope

```json
{
  "spec": "sheaf/1",
  "tenant": "acme",
  "chain": "acme/case-review",
  "seq": 18342,
  "prev": "sha256:9f2c…",
  "dossier": "cr-20261126-C104233-1",
  "type": "ai.exchange",
  "committed_at": "2026-11-26T18:04:11.204Z",
  "observed_at": "2026-11-26T18:04:09.881Z",
  "actor": { "kind": "system", "id": "acme-review-agent", "version": "1.3.0" },
  "subject": { "system": "crm", "object": "Case", "id": "C104233" },
  "artefacts": [
    { "role": "request",  "kind": "ai.exchange.raw", "sha256": "…", "bytes": 412883,
      "media_type": "application/json", "sensitivity": "client_pii" },
    { "role": "response", "kind": "ai.exchange.raw", "sha256": "…", "bytes": 18210,
      "media_type": "application/json", "sensitivity": "client_pii" }
  ],
  "body": {
    "provider": "azure-ai-foundry", "region": "example-region",
    "deployment": "…", "model": "example-model", "model_version": "2026-01-01",
    "usage": { "input_tokens": 0, "output_tokens": 0 },
    "finish_reason": "stop", "content_filter": {}
  },
  "retention": { "class": "regulated-record", "min_until": "2033-11-26" },
  "hash": "sha256:…"
}
```

The caller supplies everything except `seq`, `prev`, `committed_at` and `hash`, which only the gateway
sets. `observed_at` is the caller's clock. `committed_at` is the gateway's clock and is authoritative
for the record, but it is operator-attested: section 5.5 says what it can and cannot support.

- Every entry carries `artefacts` and `body`, empty when there is nothing to say, so "absent" and
  "empty" never differ.
- Entries in a dossier carry `subject` and `retention`, the same in every entry as in the
  dossier's `dossier.opened`. Chain-level entries carry neither.
- `actor.kind` is `system`, with a `version`, or `person`, without one.
- `actor.id` is the identity the gateway authenticated for the call that submitted the entry, and
  the gateway refuses an entry naming anyone else (7.2). A person's decision or approval is
  therefore submitted with that person's own credentials; an application acting for a person
  passes the person's token on their behalf rather than its own.
- `actor.kind` is `person` exactly when the caller's token acts for a person (a delegated token)
  rather than a workload, so no system can record itself as a person. A caller learns the identity
  its entries must name, its pseudonym where the tenant pseudonymises staff (5.7), from
  `GET /v1/me`.
- `actor.role`, when present, names the app role under which the mandate's policy grants the
  entry's type (5.6). The gateway refuses it unless the caller's token holds that role. An entry
  needs no role when the policy names its caller by id.
- An artefact reference's `media_type` is a bare `type/subtype`. Only a `document.rendition`
  reference carries `rendition_of`, the SHA-256 of what it renders.
- Times are RFC 3339 in UTC, written with `Z`; `committed_at` has milliseconds. Identifiers that
  appear in Blob paths or index tags (tenant, workflow, dossier, subject, authority) are limited
  to characters those allow, so the gateway never has to transform one.

### 5.2 Hashing and signing

- **Artefact:** SHA-256 of its exact bytes.
- **Entry:** `hash` = SHA-256 of the entry, without `hash`, canonicalised by RFC 8785 (JSON
  Canonicalization Scheme). `prev` is the `hash` of the entry with `seq − 1` in the same chain.
- **Chain start:** `seq` starts at 1, and the entry with `seq` 1 has `"prev": null`. No other entry
  may have a null `prev`.
- **Digest format:** `prev` and `hash` are `sha256:` followed by 64 lowercase hexadecimal digits. An
  artefact reference's `sha256` field is the 64 digits alone.
- **Numbers:** entries hold integers only, within ±(2^53 − 1). A value with a fraction is written as a
  string. RFC 8785 defines how to canonicalise any JSON number, but implementations in different
  languages disagree most often on floating point, and the verifier must be easy to rewrite.
- **Entry blobs:** each entry's blob is the full entry, including `hash`, in RFC 8785 form and
  newline-terminated, so two correct writers produce the same bytes.
- **Witness signature:** made by the witness identity (7.5), never the gateway, with the witness key
  (ES256, confirm at build) over the RFC 8785 canonical witness without `signature` and
  `time_attestation`, and written in base64url without padding.
- **Witness imprint:** SHA-256 of the RFC 8785 canonical witness without `time_attestation`, so it
  covers the signature. This is the only thing sent to the time-stamp authorities, and the witness
  states it in `imprint_over` so a reader need not read our code to learn what a stamp binds.

```json
{
  "spec": "sheaf/1",
  "chain": "acme/case-review",
  "witness": "daily",
  "interval": { "from": "2026-11-26T00:00:00Z", "to": "2026-11-27T00:00:00Z" },
  "last_seq": 18342,
  "last_hash": "sha256:…",
  "key_id": "acme-witness/3f1c…",
  "signature": "…",
  "time_attestation": {
    "imprint": "sha256:…",
    "imprint_over": "RFC 8785 canonical witness without time_attestation",
    "authorities": [
      { "authority": "tsa-a", "jurisdiction": "CH", "qualified": false, "obtained": true,
        "gen_time": "2026-11-27T00:03:12Z", "token_sha256": "…" },
      { "authority": "tsa-b", "jurisdiction": "JP", "obtained": false,
        "unavailable_reason": "timeout after 6 h of retries" }
    ],
    "attested_count": 1,
    "attested_jurisdictions": ["CH"],
    "distinct_jurisdictions": false
  }
}
```

The `time_attestation` block follows these rules:
- every authority asked is listed, attested or not, so "none attested" never looks like "not asked";
  the authorities asked are exactly those in the mandate;
- an authority that attested has `qualified`, `gen_time` and `token_sha256`; one that did not has
  `unavailable_reason` and nothing read from a token;
- `qualified` is read from the token (the ETSI EN 319 422 qualified time-stamp statement), never from
  configuration;
- `attested_count` and `attested_jurisdictions` (sorted, without repeats) are counted from the list;
- `distinct_jurisdictions` is a fact: true exactly when two or more authorities attested from two or
  more jurisdictions. It is not a claim about MIO-STD-01 5.3.2 (whether one order or treaty reaches
  both). That assessment is a person's, recorded in the mandate (5.6), and nothing in the record
  asserts it.

### 5.3 Entry types

| Type | Body schema covers | Rules the gateway enforces |
|---|---|---|
| `dossier.opened` | Subject, workflow version, trigger, the mandate in force (the `hash` of its `config.changed`) | First entry in a dossier; the named mandate is the one in force (5.6) |
| `source.read` | Source system, record or file identifier and version, query, what was read | Under the `reference` policy carries a fingerprint and no artefact; under `copy` the artefact must be attached |
| `artefact.attached` | Why the artefact is in the dossier | Artefact already uploaded to this tenant |
| `ai.exchange` | Provider, region, deployment, model and version, parameters, usage, finish reason, content-filter result | Request and response artefacts both present |
| `trace.recorded` | Trace identifier and span count | One `trace.otel` artefact |
| `finding.drafted` | Schema identifier of the findings artefact | The findings artefact declares that schema, which is a tenant schema of the mandate in force (5.6), and validates against it |
| `output.produced` | Where the output went (e.g. a file location) and its fingerprint | Fingerprint present |
| `decision.recorded` | Decision from a fixed set (`approve`, `approve_with_edits`, `reject`, `escalate`), reason, edits, the fingerprint of what was decided | Actor must be a person, not a system; the decided fingerprint must exist in this dossier |
| `config.changed` | What changed (the mandate parts, 5.6), the new version, the old version and the `hash` of its `config.changed`, who approved, and a digest of each mandate part and of the whole | Approver must be the actor, a person (5.1); the **whole** mandate attached as artefacts and complete against schema `sheaf.mandate/1`; the parts named as changed are exactly those whose digest changed; the first entry of every chain (with no old version); one change waits at a time; applied only after its `witness.interim` (5.6) |
| `correction` | The entry it corrects and why | Target entry exists in a dossier; never edits, only supersedes. In another dossier only if the target's dossier is sealed and has the same subject |
| `notice` | Failure, retry, pause, resume, restart, an authority that did not answer | In a dossier, or at chain level when it concerns no unit of work |
| `dossier.sealed` | Final status (`completed`, `failed`, `abandoned`), the number of entries in the dossier including this one, and of distinct artefacts it refers to | Last entry; counts are true; the gateway then accepts nothing more for the dossier |
| `witness.daily` | The witness itself (5.2): interval, last `seq`, last `hash`, key, signature, and the time attestation with each authority asked | Submitted only by the witness identity. The gateway checks the signature against the witness key in the mandate, and every token, before it commits (7.2). The interval is one UTC day, written `YYYY-MM-DDT00:00:00Z` to the next, ended before commit, starting where the last daily witness ended (the genesis day for the first); `last_seq` is the last entry committed before the interval ends |
| `witness.interim` | As `witness.daily`, for one entry, with no interval | Always after a `config.changed`; after each `dossier.sealed` if the mandate says so. Each entry at most once. Otherwise as `witness.daily` |
| `retention.expired` | Retention class, `min_until`, retention policy version, the dossier ids and artefact SHA-256s about to be deleted, who approved. No personal data | Written before any lifecycle deletion. Approver must be the actor, a person (5.1); every listed item's retention has passed; no live dossier still refers to a listed artefact (5.7) |

Chain-level entries (`config.changed`, `witness.*`, `retention.expired`, and a `notice` that
concerns no dossier) carry `"dossier": null` and are kept in full in
`dossiers/{workflow}/{yyyy}/_chain/`, so the verifier can recompute their hashes.

**A dossier's fingerprints** are the SHA-256s of the artefacts its entries refer to and the
fingerprints recorded in its `source.read` and `output.produced` entries. A decision, and a
rendition, names one of them.

**Schemas.** The envelope, each entry type's body and artefacts, the witness (`sheaf.witness/1`),
the mandate (`sheaf.mandate/1`) and `sheaf.record-snapshot/1` are JSON Schema 2020-12 documents in
the registry, snapshotted into each tenant's container (4), and are normative. The rules in the
table that a schema cannot express (those that relate one field to another, or need the chain so
far) are enforced by `sheaf_core`, which the gateway and the verifier share. A validator of these
schemas must assert `format` for `date-time` and `date`, so 30 February and 24:00 are refused; a
leap second is refused too. A `pattern` is read as ECMA-262 reads it: its end anchor is the end of
the string. Values nest at most 64 deep.

**Tenant schemas.** A tenant's own schemas, such as one for its findings, are `schema.json`
artefacts named in its mandate (5.6). Each is a JSON Schema 2020-12 document whose identifier is
the tenant, a dot, a name, a slash and a major version (`acme.findings/1`), and whose `$id` is
`urn:sheaf:` and that identifier; names starting `sheaf.` are the registry's. A tenant schema may
refer to the registry and to the mandate's other schemas, and to nothing else, so a verifier
needs nothing outside the container. The same validation rules apply.

### 5.4 Source capture policy

Set per tenant and workflow in the gateway's policy file and recorded in every `dossier.opened` entry.

| Policy | Source document | Use when |
|---|---|---|
| `reference` | Identifier, version and SHA-256 recorded; bytes not copied. The reader opens the original from the source system | The customer's contract promises no copies |
| `copy` | Bytes stored as an artefact | The source system may change or delete the original before the retention period ends |

### 5.5 Time, and how far it can be trusted

Every time the record supports has a **grade**, after MIO-STD-01 5.7: **A** when an authority outside
the operator attested it, **O** when it rests on the operator's word, here the gateway's clock and
sequencing.

| Claim | Grade | Why |
|---|---|---|
| An entry existed no later than the earliest valid `gen_time` on the first witness that covers it | A | Two authorities stamped a witness that commits to it through the chain |
| An entry later in the chain than a `witness.*` entry was committed after that witness's `gen_time` | A | It chains through the `witness.*` entry, which carries the token digests, and nobody could know those before the stamp existed |
| So each entry has a window: between the last stamp before it in the chain and the first stamp after it. At one-day intervals, about a day | A | From the two rows above |
| `committed_at`, and the order of entries within one window | O | The gateway's clock and sequencing, before anyone outside saw them |
| `observed_at` | O | The caller's clock |
| B came after A, where B contains A's digest (a decision names the draft's fingerprint) | Any | A digest cannot be written before the thing it fingerprints exists |

**The witness interval is an evidentiary choice, not a tuning knob** (MIO-STD-01 5.6, 5.8). It is
recorded in the mandate. At one UTC day the record gives up, at grade A, the time of day of every
event, and the order of events within a day unless one contains the other's digest. For example,
whether two same-day decisions on one case were made in the order recorded rests on the gateway's
clock. Interim witnesses narrow the interval where it matters: always after a
`config.changed` (5.6), and after each `dossier.sealed` if the tenant's mandate says so, which gives
each dossier a grade-A time of completion.

A reader shows the grade beside every time it displays, and never presents a grade-O time as
independently attested.

### 5.6 The mandate

The **mandate** is everything that fixes what a workflow may do and how it is recorded:
- the gateway policy file: callers by id and app roles, the entry types each may write, kinds,
  size limits, source capture, sensitivity rules. A role lets people be added or removed in the
  tenant's directory without a new mandate;
- the instructions and rules as given to the model, verbatim;
- the tenant's own JSON Schemas, such as the one its findings follow (5.3);
- the model configuration: provider, region, deployment, model and version, parameters;
- the kind registry version, the retention classes and the witness interval;
- the witness public key, and the time-stamp authorities with their jurisdictions, certificates,
  practice statements and a person's assessment against MIO-STD-01 5.3.2.

Each `config.changed` attaches the **whole** mandate as artefacts (`data.json` under schema
`sheaf.mandate/1`, with instructions as `text.markdown` and tenant schemas as `schema.json`), not a
diff. The mandate's parts are `policy`, `instructions`, `schemas`, `models`, `registry`,
`retention`, `witness_interval`, `witness_key`,
`authorities`, `personal_data` and `gateway` (the image digest, 7.1). A part's digest is the
SHA-256 of its RFC 8785 form, written like an entry's `hash`; a part that names an artefact or a
file in `trust/` by its SHA-256 covers those bytes too. Integers only, as in entries. The mandate
names at least two authorities, in at least two jurisdictions (5.5). The witness key and each
certificate the mandate pins are stored in `trust/` before the `config.changed` that names them,
which the gateway refuses otherwise, so every witness under that mandate can be checked. So the question "what was this
agent permitted to do at entry N" is answered from the container alone: the latest `config.changed`
whose `witness.interim` comes before N, whose artefacts the verifier checks against the digests in
its body (MIO-STD-01 6.3).

- **Genesis.** The first entry of every chain is a `config.changed` with no old version, approved by a
  named person.
- **Fixed before it applies.** The gateway applies a new mandate only after its `witness.interim` is
  committed, so every entry under it provably came after it was stamped (MIO-STD-01 6.2, at grade A).
  That interim witness is signed with the new mandate's key and lists its authorities; every other
  witness uses the mandate in force. Until it is committed, the previous mandate stays in force,
  and before the genesis mandate's is committed, only witness entries and `notice` may be written.
  If no authority answers, the change waits and the gateway writes a `notice`.
- **Enforced, not only recorded.** The gateway rejects any write the policy does not permit. MIO-STD-01
  requires only that the mandate be recorded.
- **What it cannot see** (MIO-STD-01 6.5). Actor identifiers are workload identities and user
  accounts, not agents. An agent or script acting with a person's credentials (for example, a
  process saving a reviewed document under the reviewer's own account) is recorded as that person,
  and the record cannot tell the two apart. This is disclosed, not closed.

### 5.7 Expiry, deletion and personal data

**Expiry is recorded before anything is deleted** (adapted from MIO-STD-01 4.6.4, which records the
destruction of a pseudonym key; this record has no such keys yet, so it records expiry). The
lifecycle step first asks the gateway to commit a `retention.expired` entry naming every dossier and
artefact to be deleted, their class and `min_until`, the retention policy version and the person who
approved. It carries identifiers and digests only. Only then are the blobs deleted. Chain segments,
`_chain` dossiers and witnesses stay for the tenant's longest class, so the chain stays continuous and
checkable after its dossiers have gone.

The verifier can then tell lawful deletion from tampering: a missing blob covered by a
`retention.expired` whose dates have passed is reported as expired; any other missing blob is a
failure.

**Personal data in sealed fields** (MIO-STD-01 4.6.1, 4.6.2). Two kinds of identifier can be sealed
in clear:
- **Staff:** `actor` in `decision.recorded` is the account of the person who decided, which is staff
  personal information.
- **Clients, indirectly:** a subject identifier in `subject` that the customer can link to a person.

A tenant either keeps them in clear, on the basis of its record-keeping obligation and the record's
purpose (showing who decided), or seals a keyed pseudonym under a per-person secret in its Key Vault
(4.6.2), with erasure by destroying the secret (4.6.3). The second costs a key that must survive the
whole retention period, without which the record cannot say who decided anything, and every reader
then needs that key to show a name. The first costs a lookup that must also last: in clear, a
person is recorded by their Entra object ID (7.1), and Entra forgets a deleted account, so the
tenant keeps its own record of which person each object ID belonged to for the whole retention
period, or the record can no longer say who decided. Either way the choice and its basis are
recorded in the mandate (5.6), and it must be made before the tenant's first write. The gateway is
deployed with the same choice and refuses a mandate that declares the other.

Pseudonymised, a person is recorded as `ps-` and the first 32 hexadecimal digits of HMAC-SHA256,
keyed by a secret of their own in the tenant's Key Vault, over their Entra object ID. The gateway
creates the secret the first time it sees the person and never replaces it, so each person has one
pseudonym; destroying the secret erases them. The gateway does not rewrite an entry: it works out
the identity the entry must name and refuses one that names another (5.1). Workload identities are
not personal data and are recorded in clear.

A subject is pseudonymised the same way, under a secret of its own per subject record (its system,
object and id), so erasing a client means destroying the secrets of their records. A caller the
mandate in force knows gets a subject's pseudonym from `POST /v1/pseudonyms`; the gateway never
records the clear id. Under a mandate that pseudonymises, every person named as `actor`, every
`subject.id`, and the person who signed the mandate's authority assessment must be in that form
(`ps-` and 32 hexadecimal digits); the gateway refuses anything else, and the verifier checks it
again.

**Dossier ids never embed the subject** (for example `cr-20261126-7Q2MZK`, not
`cr-20261126-C104233-1`). Dossier ids sit in chain segments, which outlive the dossier, so an id that
embeds a subject would keep naming it after the dossier has expired. The gateway rejects a
`dossier.opened` whose id contains its subject's identifier.

## 6 Kind registry, v1

Every artefact is one of these kinds. The registry is versioned (semver); a minor version may add
kinds or optional fields, and a major version is a new `spec`.

| Kind | Media types | Gateway validation |
|---|---|---|
| `document.pdf` | `application/pdf` | Magic bytes; parses; page count; not encrypted. JavaScript, embedded files and launch actions rejected or flagged per tenant policy |
| `document.office` | DOCX, XLSX (OOXML) | Valid OOXML package; macro-enabled formats rejected; external links flagged |
| `document.rendition` | `application/pdf` | As `document.pdf`, plus `rendition_of` pointing to an artefact in the same dossier |
| `image.raster` | `image/png`, `image/jpeg`, `image/webp` | Decodes; pixel-count limit. SVG not allowed |
| `text.plain`, `text.markdown` | `text/plain`, `text/markdown`; UTF-8 | Valid UTF-8; size limit |
| `data.json` | `application/json` | Parses; declares a `$schema` registered in the registry or a tenant schema of the mandate in force; validates (JSON Schema 2020-12) |
| `schema.json` | `application/schema+json` | Parses; a JSON Schema 2020-12 document with a tenant schema `$id` (5.3); uploaded with a `config.changed` |
| `record.snapshot` | `application/json` | Schema `sheaf.record-snapshot/1`: system, object, identifier, fields, retrieved-at, query |
| `ai.exchange.raw` | `application/json` | Parses; size limit; provider family known |
| `trace.otel` | OTLP/JSON | Valid OTLP trace; span identifiers and parents consistent; OpenTelemetry GenAI semantic-convention version pinned in the registry |
| `message.email` | `message/rfc822` | Parses headers; size limit. **Deferred to v1.1** |

Size limits per kind are set in the registry. Anything bigger is rejected, not truncated.

**Display hints.** A JSON Schema registered for `data.json` may carry a display hint (`table`,
`key-value` or `tree`) that readers may use. How a reader renders each kind is the reader's own
business. Every reader must treat artefact bytes as untrusted, even
though the gateway validated them.

**Sensitivity** is declared per artefact: `client_pii`, `staff_pii` or `none`. The gateway's link
issuer (section 8) and readers use it to decide who may open the artefact; it does not change how it
is stored.

## 7 The write gateway

### 7.1 Where it runs and who can write

- In the tenant's own Azure subscription and region, as a container. One gateway per chain, so
  one per workflow, all running the same image, whose digest is recorded in the mandate (5.6) so
  the code that validated any entry is known.
- Its managed identity is the **only** identity with write access to the `evidence` container: a
  role that can create and read but not delete (immutability blocks deletion anyway).
- **No other workload may be able to obtain that identity.** On a virtual machine, any process can
  get a token for any managed identity assigned to the machine through the instance metadata
  service, so a caller sharing the gateway's machine could write to storage directly and skip
  validation. The gateway therefore runs as its own Azure resource.
- **Reference deployment:** an Azure Container Apps app with internal ingress only, inside the
  tenant's virtual network; the storage account reached through a private endpoint; one replica,
  since a chain has one writer anyway. Its write-ahead journal and the chain-head lease live in a
  separate, mutable `gateway-state` container that only the gateway can write, because a replica's
  local disk does not survive a restart. The witness (7.5) runs as a scheduled Container Apps job
  from the same image, with its own identity.
- Callers authenticate to it with Entra ID: systems with a workload identity, people with their own
  token. The mandate's policy lists which callers, by id or by app role, may write which entry
  types, and each entry's actor is the caller that submitted it.

### 7.2 The pipeline

1. **Upload each artefact.** The caller sends its bytes with the declared SHA-256, kind, media type
   and sensitivity, plus an idempotency key. The gateway holds the bytes in a temporary area of its
   own, not in Blob, and then:
   - recomputes the SHA-256 and rejects any mismatch;
   - sniffs the real type from the bytes and rejects any mismatch with the declared one;
   - runs the kind's validator and size limit.

   If every check passes, it writes the blob (or, if that SHA-256 already exists, leaves it as
   stored), sets `Content-Type`, metadata and tags, and returns an artefact receipt. Its retention
   is set when an entry refers to it (4). If any
   check fails, nothing is written and the caller gets an error code.
2. **Commit the entry.** The caller sends the envelope without chain fields, and may send an
   idempotency key so that a retry gets the first receipt rather than a second entry. The gateway
   then:
   - validates the envelope, and the body against its type's schema;
   - checks the entry's `actor.id` is the authenticated caller and any `actor.role` is one its
     token holds (5.1), and that the mandate's policy grants the type to that id or role;
   - checks every artefact reference exists in this tenant;
   - checks the dossier is open, and applies the type's rules (section 5.3).
3. **Chain it.** Under an exclusive lease on the chain head, the gateway:
   1. sets `seq`, `prev` and `committed_at`, and computes `hash`;
   2. writes the entry's blob, then its record in the day's chain segment, each once;
   3. advances the head and releases the lease.

   A write-ahead journal on the gateway lets it finish a half-committed entry after a restart,
   including one whose segment record was written but whose witness files or retention were not.
   Until it has, the gateway commits nothing more: committing again would reuse the `seq`.
4. **Receipt and event.** The gateway returns the entry receipt (`seq`, `hash`) to the caller, and
   publishes a content-free event to subscribed readers: `{ tenant, workflow, seq, dossier,
   type, hash }`. A failure to publish never fails the commit.
5. **Witness.** At the end of each witness interval, after each `config.changed`, and after each
   `dossier.sealed` if the tenant chooses, the witness identity (7.5):
   1. reads the chain from its last witnessed `seq` to the head, read-only, and checks it is
      continuous, so it never signs a chain it has not followed;
   2. builds the witness (5.2) and signs it with the witness key, which the gateway cannot use;
   3. asks each authority in the mandate for an RFC 3161 time-stamp over the witness imprint, with a
      random nonce. Only the 32-byte imprint leaves the tenant: no content, no personal data, nothing
      naming the tenant. It also fetches each authority's revocation status;
   4. submits the signed witness, the tokens and the revocation status to the gateway.

   The gateway checks the signature against the witness key in the mandate, and each token (imprint,
   signature, certificate chain to the root in `trust/tsa/`, and that it is the token the witness
   lists), commits the `witness.daily` or `witness.interim` entry, and then writes the tokens and
   the witness file. They are written after the entry because they are write-once: a failed attempt
   must leave nothing that blocks the retry, whose tokens differ. A failure between the two halts
   the gateway, as in step 3. It then emails the daily witness to the
   tenant's nominated person and sends it to each outside witness holder the tenant names,
   which keeps its own copy beyond the tenant's control.

   If an authority does not answer, the witness retries for six hours by default, then
   lists the authority as not obtained, with the reason, and alerts; the gateway writes a `notice`. A witness with
   fewer than two attesting authorities, or with only one jurisdiction, is still committed. The
   verifier reports that interval as below this standard rather than hiding it.

### 7.3 When the gateway is down

The caller **fails closed**: it queues entries locally and does not publish anything (no draft, no
email) whose evidence has not been committed. This is what the audit trail specification's "in
place before any automated workflow acts" means in practice.

### 7.4 Optional malware scanning

Kind validators already restrict content to safe, parseable formats. A tenant that wants more can
add on-upload malware scanning on the storage account; the gateway then waits for a clean result
before returning a receipt.

### 7.5 The witness signer

MIO-STD-01 4.3 asks that the signing capability be outside every write path. Here the gateway
writes and cannot sign, and the witness signs and cannot write.

| | Gateway identity | Witness identity |
|---|---|---|
| `evidence` container | Create and read; no delete | Read only |
| Witness key | None | Sign only (a custom role with the key `sign` data action, and `read` for its public key; no other key operation) |
| Gateway API | n/a | May submit `witness.*` entries only |

- **The key** is an Azure Key Vault key in the tenant's subscription and region, EC P-256 (ES256,
  confirm at build), created without a release policy so it cannot be exported. Its public key is
  stored in `trust/witness-keys/` and its fingerprint is in the mandate. Rotating it is a
  `config.changed`.
- **The witness runs apart from the gateway.** On a virtual machine, any process can get a token for
  any managed identity assigned to that machine through the instance metadata service, so the witness
  cannot share the gateway's server. It runs as its own Azure resource with its own identity (for
  example a scheduled container job), which the gateway's server does not hold.
- **Key Vault logs every sign operation** to a workspace the gateway cannot write, so a signature
  nobody expected is visible.

What this buys, honestly: a compromised gateway, or anyone holding only its identity, cannot
witness a history of its own making. It separates identities, not organisations: whoever owns the
subscription can reassign roles, and that shows in the Azure activity log. What stops the operator
moving a record in time is the two authorities' stamps, not the key.

## 8 Reading: the contract on the customer's side

This is the whole interface between the gateway and any reader. A reader gets
**read-only** access and these ways in:

| Need | How |
|---|---|
| Know something new arrived | The gateway's content-free events; or list `chain/{workflow}/{yyyy}/{mm}/{dd}/` |
| Catch up after downtime | Read chain segments from the last `seq` it holds |
| Find dossiers | Find Blobs by Tags (e.g. `subject_id`, `owner`, `subject_date` range), or list by prefix |
| Open evidence | A short-lived, read-only, single-blob link issued by the gateway after it checks the viewer's role and the artefact's sensitivity, so content goes from the customer's storage straight to the browser |
| Verify | Recompute artefact and entry hashes and chain continuity from Blob, and check them against the witnesses, their signatures and their time-stamp tokens |
| Keep an outside witness copy | Receive each daily witness from the gateway (7.2), and fetch its tokens from `witness/` |

**Events are hints.** They carry no content and are not signed into the record. A reader treats one
as a prompt to read storage, never as the fact itself, and catches up from the chain when events are
missed.

**Opening evidence.** A reader asks the gateway for a link, naming the viewer. The gateway checks the
viewer's role against the artefact's sensitivity under the tenant's policy and issues a user
delegation SAS for that one blob, read-only, for minutes. How the gateway learns the viewer's role,
from the reader's word or from the viewer's own Entra token, is not fixed by this draft. The gateway logs each
link it issues in its own operational log, not in the chain: a record of who looked at what is a
record of people's attention and needs its own access rule before anyone uses it (MIO-STD-01 Annex
B.6).

A reader's own index (search, joins, summaries) is built from these reads, must be rebuildable from
scratch at any time, and must not outlive the record: when a `retention.expired` names a dossier, the
reader drops what it holds of it.

## 9 Verification and exit

The verifier is published with the standard and stored in each tenant's container. Given the
container, or a downloaded copy of it, it:

1. recomputes every artefact's SHA-256 and every entry's `hash`;
2. checks chain continuity across all segments, that every dossier entry appears in the chain, and
   that every missing dossier or artefact is covered by a `retention.expired` whose dates have
   passed;
3. checks each witness: its signature against the witness key in the mandate in force (for the
   interim witness that applies a new mandate, that mandate's key), its last
   `seq` and `hash` against the chain, and any outside witness copies supplied;
4. checks **every** time-stamp token offline, not just the first that passes: the CMS signature; the
   certificate chain to the authority's root in `trust/tsa/`, not the system store; the time-stamping
   key usage; the message imprint against the recomputed witness imprint; the certificate's validity
   at `gen_time`; and revocation against the status captured at stamping, where stored. It reports
   any `gen_time` earlier than the `committed_at` of an entry the token covers, which means the
   gateway's clock or the record is wrong;
5. counts, per interval, the authorities whose tokens verified and their distinct jurisdictions;
6. rebuilds the mandate in force at each entry and checks its artefacts against its digests;
7. validates every artefact and entry against the registry snapshot of its version; and
8. reports pass or fail per dossier and per interval, with the statement below.

**What every report says** (MIO-STD-01 8.4):

> **What a pass shows.** Every artefact and entry checked is exactly what was committed. The chain is
> complete from its first entry to the last witnessed one. Each witnessed interval existed no later
> than the stamp times shown, attested by the authorities and jurisdictions listed. The mandate shown
> was in force at each entry. Anything missing was removed after a recorded expiry.
>
> **What a pass does not show.** That any content was true, complete, or the only evidence, before it
> was committed. The time of day, or the order within one witness interval, of any event, which rests
> on the gateway's clock, except where one entry contains another's digest. Anything written after the
> last witness. That an actor identifier was the agent that acted: an agent using a person's
> credentials is recorded as that person. That an actor held the role its entry names: the
> gateway checked the caller's token, and the record keeps the role, not the token. That no single order or treaty can reach both authorities:
> that is a person's assessment, recorded in the mandate and not checked here. The record evidences
> what occurred. It does not prevent harm.

It needs Python and the container, and nothing from any reader, from the gateway's authors or from Microsoft beyond reading Blob.
The token checks need a small dependency set, `cryptography` and `asn1crypto`, pinned by hash and
shipped as wheels in `verifier/{version}/vendor/`, so a check in seven
years does not depend on a package index still serving them. The instructions show how to cross-check
any token with `openssl ts -verify` against the same stored root.

An export for a regulator is the container contents (or a subset by dossier, with the `_chain`
dossiers, chain segments, witnesses and `trust/`) plus the verifier.

## 10 Versioning and change

- Every entry carries `spec`. A dossier never changes version mid-way.
- The registry is semver. Minor versions add kinds or optional fields. Major versions mean a new
  `spec`, and old dossiers stay valid under theirs.
- Every registry version in use is snapshotted into the tenant's container on first use.
- Changing a tenant's policy (source capture, sensitivity rules, size limits, witness interval,
  authorities, witness key) is a `config.changed` entry approved by a named person, carrying the
  whole new mandate (5.6).

## 11 Confirm at build

All in the tenant's region, before the storage policy is locked. Checked in New Zealand North on
16 November 2026, with unlocked policies: per-blob retention set and extended on block blobs, and a
delete refused under it; index tags changed and found by tag under immutability; the Cold tier under
immutability; a Key Vault ES256 signature; Entra v2 access tokens. The same check found that
append blobs refuse appends and sealing under version-level immutability, hence one blob per entry.
A second check that day ran that layout end to end: the gateway on Blob, a restart rebuilt from
the container alone, a crash between an entry blob and its segment record finished from the
journal once the dead gateway's lease expired, and the witness job following the day's folders,
signing with the Key Vault key and stamped by the three default authorities.

| Behaviour relied on | Section |
|---|---|
| Version-level immutability on the `evidence` container, with per-blob retention set and extended by the gateway on block blobs | 4 |
| Index tags can be set on blobs under immutability, and Find Blobs by Tags returns results consistently enough for a reader | 4, 8 |
| Changing access tier is allowed on immutable blobs, and the Cold tier supports version-level immutability | 4 |
| User delegation SAS lifetime and scope for single-blob, read-only links | 8 |
| Availability and price of on-upload malware scanning | 7.4 |
| A Key Vault EC P-256 key created with no release policy cannot be exported | 7.5 |
| A custom role holding only the key `sign` and `read` data actions works for a managed identity, and gives no other key operation | 7.5 |
| Key Vault diagnostic logs record every sign operation, to a workspace the gateway's identity cannot write | 7.5 |
| A compute option with its own managed identity, separate from the gateway, available in the tenant's region for the witness | 7.5 |
| Outbound access from the witness to the chosen authorities' RFC 3161 endpoints, and their retry behaviour | 7.2 |
| The pinned Python set verifies each chosen authority's tokens offline, including the qualified time-stamp statement, and agrees with `openssl ts -verify` | 5.2, 9 |
