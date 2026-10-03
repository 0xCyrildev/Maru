# Claim format

A Maru claim is the `predicate` of an in-toto v1 Statement, carried in a DSSE envelope.

```jsonc
{
  "maru": "maru/claim/v1",
  "claimId": "sha256 over the projection — content identity, tool-independent",
  "registryMajor": 1,
  "channel": "assert" | "assume",
  "predicate": "move.value.control",
  "subjectUri": "sui:function|0x1017…12405|leak|leak_mut",
  "args": { "package": "0x1017…12405" },        // encoded, registry-declared names
  "value": "caller",
  "lineage": { "facet": "source:parameter-list|…", "key": "sha256(facet)",
               "basis": "derived" | "declared", "note": null },
  "witness": "eligible" | "report-only",
  "declaredByEmitter": "eligible" | "report-only",
  "verifiability": "full" | "partial",
  "unverifiableFields": [ { "field": "parentObject", "reason": "conditional" } ],
  "coercedFields": [ "amount" ],
  "droppedFields": [ { "field": "note", "reason": "prose" } ],
  "provenance": "deterministic" | "rules" | "model" | "fallback",
  "methodology": { "tool": "move-static", "toolVersion": "0.0.1",
                   "check": "handle-supply", "checkVersion": "0.0.1", "emitter": "static-source" },
  "target": { "kind": "transaction", "network": "testnet", "digest": "9gwF…" },
  "severitySignal": "high",                      // carried from the emitter, never merged
  "findingMessage": "…",                          // what the finding pointed at, never hashed
  "limits": [ { "id": "limit.move-static.regex-not-compiler", "text": "…" } ],
  "evidence": { "params": "vault:&mut Vault" },   // observation only, never compared
  "emittedAt": "2026-10-02T00:00:00.000Z"
}
```

## Identity

```
projection = join("\x1e",
  "maru/claim/v1", registryMajor, predicate, subjectUri,
  "${argCount}:${arg1}\x1e arg2…", value, channel)
claimId    = sha256hex(projection)
```

- **Included:** predicate, subject, declared arguments in order, value, channel, registry major.
- **Excluded on purpose:** tool (so two tools saying the same thing share an id and agreement is
  detectable), severity (a re-rating must not renumber a finding), evidence and `emittedAt`.
- `channel` is included: an assumption and an assertion about the same fact are different statements.

Canonicalization exists **only** for this fixed projection, via one encoder per argument
(`network · hexaddress · digest · txdigest · decimal · signeddecimal · token · typestring · csvsorted · uri`).
Arbitrary evidence is never hashed. DSSE signs the payload bytes as they are, so no JSON canonicalizer is
ever in the trust path.

## Three field categories, because "we ignored it" and "we could not pin it" differ

| Category | Meaning | Consequence |
|---|---|---|
| `unverifiableFields` | identity-bearing and not pinnable — truncation-sampled arrays, embedded opaque objects, keys that exist only for some data shapes | `verifiability: partial` → **never a witness**, still reported |
| `coercedFields` | raw type varied in the source (a bigint arriving as a number) and was canonicalized | auditable, does not affect verifiability |
| `droppedFields` | carried nothing the predicate models (prose, or outside the projection) | recorded so the reader sees what was left out |

A prose field is not a defect. An *unpinnable subject* is, and a claim whose subject cannot be pinned is
not a second opinion — which is why partial claims survive in the output but cannot corroborate anything.

## Subjects

Namespaced, part-count-checked, `|`-separated. `|` is refused by every encoder, so a boundary can never be
ambiguous — and `:` cannot be used, because a Move type string is `0x2::coin::Coin<0x2::sui::SUI>` and a
qualified function is `pkg::m::f`.

| Kind | Parts |
|---|---|
| `sui:object` | objectId |
| `sui:function` | package, module, function |
| `sui:package-module` | package, module |
| `sui:address-coin` | address, coinType |
| `sui:event-type` | eventType |
| `sui:transaction` | digest (base58, case-sensitive, never lowercased) |

## Refusals

Every refusal is a typed error with a stable code; nothing is coerced to a default. `buildClaim` is the
only admission point.

| Code | Trigger |
|---|---|
| `UNKNOWN_PREDICATE` | predicate absent from `core@1` |
| `UNKNOWN_REGISTRY_MAJOR` | claim requires a different major than this build speaks |
| `UNKNOWN_VALUE` | value outside the declared domain (or outside the shared domain of a conflict group) |
| `UNKNOWN_EMITTER_KIND` | emitter kind not declared |
| `MALFORMED_CLAIM` | extra/missing argument, subject in the wrong namespace, an emitter asserting a predicate only another mechanism may determine, an assumption marked witness-eligible |
| `SIGNATURE_INVALID` | signature does not verify over `PAEv1(payloadType, payload)` |
| `UNREGISTERED_KEY` | signature is valid and the key is pinned nowhere |
| `TOOL_KEY_MISMATCH` | the claim names tool X, the key is pinned to tool Y — at signing **and** at verification |
| `PROJECTION_MISMATCH` | stored `claimId` ≠ recomputed: identity fields edited after signing, or an encoder changed |
| `UNCLASSIFIED_EVIDENCE` | an adapter met an evidence field it has no rule for |

`UNKNOWN_VALUE` on a *space* rather than a predicate means a token outside a conflict group's shared domain:
two spellings of a value in one group are a formatting dispute for a human, never a complement relation.

## Envelope

```jsonc
// in-toto Statement
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [ { "uri": "maru:claim/<claimId>", "digest": { "sha256": "<claimId>" } } ],
  "predicateType": "https://maru.dev/predicate/finding/v1",
  "predicate": { /* the claim above */ } }

// DSSE envelope
{ "payloadType": "application/vnd.in-toto+json", "payload": "<base64 statement bytes>",
  "signatures": [ { "keyid": "maru:<rfc7638 thumbprint>", "sig": "<base64 ed25519>" } ] }
```

The subject is the claim's own projection because an in-toto subject digest must be a content digest and
Maru refuses to synthesize one for a transaction it did not hash. The on-chain target travels in
`predicate.target`, where it can be checked.

A **claimset** is `{ "maru": "maru/claimset/v1", envelopes: [...], coverage: [...] }` — several signed
claims plus the completeness records that travel with them.
