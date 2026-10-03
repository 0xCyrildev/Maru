# Trust model and adoption

## What verification proves, and what it does not

`maru verify` runs three independent checks and requires all three:

1. the signature is valid over `PAEv1(payloadType, payloadBytes)`;
2. the key that made it is **pinned in the ring**, and the claim's `methodology.tool` equals the tool that
   key is pinned to (`TOOL_KEY_MISMATCH` fires both at signing and at verification);
3. the claim's `claimId` recomputes from its own identity fields.

That establishes attribution and internal consistency. **It does not establish that the claim is true.** The
CLI prints this, because a green verify is exactly the thing a reader will otherwise over-read.

## Keys without PKI

```jsonc
// ~/.maru/keyring.json
{ "maru": "maru/keyring/v1",
  "entries": [ { "toolId": "chase", "keyId": "maru:<rfc7638 thumbprint>",
                 "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…" },
                 "addedAt": "…", "note": "who pinned it and why" } ] }
```

- `keyId` is the JWK thumbprint (SHA-256 over lexicographically ordered `crv`/`kty`/`x`, base64url), so a
  keyid cannot be claimed by hand. Parsing a ring **re-derives** every thumbprint and refuses a mismatched
  pairing: a hand-edited entry is a bug, not a trust decision.
- Identity is derived from the key, never from a name. A tool that says it is `chase` is `chase` only once
  a pinned key says so.
- Trust is local and auditable. No Sigstore, no on-chain anchor, no CA, no discovery. Adding an entry is a
  human act on a file a human reads.
- v0 has **no rotation and no revocation**. `maru key drop` stops future attribution; everything the dropped
  key signed still verifies forever. This is a real limit, and the reason `emit` refuses to sign with an
  unpinned key rather than producing something nobody can check.

## Provenance, not confidence

`confidence` is one word doing three jobs in most tooling, so Maru does not have it. It has
`provenance`, an ordered statement of *how the emitter came to know*:

| Value | Means | May witness |
|---|---|---|
| `deterministic` | structure or a resolved signature decided it | yes |
| `rules` | a name-matched table decided it | yes, and shown as such |
| `model` | a language model read it | **never** |
| `fallback` | the model path failed and something was emitted anyway | **never** |

Conversion is not a value in this ladder. An importer inherits whatever provenance its source stated, so
the rule keys on `methodology.emitter: "imported"` instead — a field an adapter sets and cannot inherit.
`exclusionReason()` once tested `provenance === "imported"`, which nothing ever set; the registry kept it
harmless by admitting no `imported` emitter on any collidable predicate, and a test now pins that invariant.

`declaredByEmitter` records what the tool asked for before any downgrade, so a reader can tell "the tool
declined to vouch for this" apart from "the protocol overruled the tool" — only the second is something the
tool's author should argue with.

Model readings are excluded because the assertion channel and the verification channel must not be the same
channel: a model cannot corroborate a model. This also sets the honest adoption ceiling — the LLM audit
*skills* in the tool list can emit assumptions, limits and provenance honestly, and contribute nothing to
corroboration. A tool that wants its readings to witness must publish a deterministic check, not a prompt.

## Methodology: what a tool must publish

1. `methodology.check` — a stable id per check, versioned, referenced by every claim.
2. `limits[]` — stable ids, not prose alone, so another tool can say "I falsified the premise behind
   `limit.mutable-access.indirect-paths`".
3. `witness` per check — *may this shape witness anything?* Chase's `corroborates: false` is exactly this
   declaration, and the adapter recovers it from the detector table rather than guessing it from counts.
4. which registry predicates it may **assert** and which it may only **assume**.

`assumptions` are emitted as claims in `channel: "assume"`. An adapter may declare a premise about a
detector's findings; that is the adapter's claim about the premise, it carries a note, and the methodology
owner is entitled to disagree. What is not allowed is a premise that stays inside a message string where no
other tool can reach it.

## Adapter contract

An adapter is the only place a tool's own shapes meet the registry, and it must:

1. **Classify every evidence field it sees** into projected / coerced / dropped / unverifiable. An
   unclassified field raises `UNCLASSIFIED_EVIDENCE` and stops the run — a silently dropped field is a
   claim about having seen everything.
2. **Never invent a subject.** No identity in the data ⇒ no composable claim; the finding is carried, and
   the reason is printed.
3. **Aggregate before asserting.** Two rows that cannot both hold (a field created and deleted) become one
   `cycle`, not a contradiction with itself.
4. **Say which input it was given.** Facts come from a trace, signals from a report; a report-only input
   emits a coverage record saying no fact layer was derived, so nothing there can corroborate.
5. **Refuse missing context instead of defaulting it.** No network ⇒ stop. An unmapped named address ⇒
   skip that module and print why. A guessed subject is worse than a missing one.

## Adding a predicate

1. Add it to `src/registry/core.ts` with its subject kind, argument encoders, domain, conflict mode, group,
   emitters and `assertEmitters`.
2. Bump **major** if you remove a value, change a subject kind, or change a complement relation. Adding a
   predicate or a token is a **minor**: consumers refuse on major mismatch, so `core@2` claims are simply
   unreadable by `core@1` rather than misread.
3. Add a constructible sample per predicate (the unit suite asserts the sample table covers the registry
   *exactly*) and at least one fixture, including a must-not-fire case.
4. Run `MARU_UPDATE_GOLDENS=1 npm run conformance`, then read the golden diff: any claimId that moved is
   an identity change, which is a major bump, not a refactor.

## Adding an emitter

Build claims → sign each as an in-toto statement in a DSSE envelope → publish a keyring entry → run the
conformance suite against your own fixtures. Composition is asymmetric on purpose: a new tool is not
trusted because it joined; its claims only count where its key is pinned and its mechanism is entitled to
speak the predicate.

## Adopting from the existing list

- **Tools already emitting SARIF**: `maru sarif import` converts what is projectable and refuses the rest
  with a reason. Conversion is not composition — file-and-region findings need their own subject namespace
  and their own predicates before they can collide with anything.
- **Tools emitting JSON findings**: write an adapter implementing the contract above. Start by emitting
  `move.finding.signal` claims (carried, non-colliding) so the pipeline is live, then add fact predicates
  as real subjects appear.
- **Sui/Move tools**: `sui replay` output is a natural source of determined fact claims, and a replay
  artifact digest is the one thing that could later become a genuine in-toto subject — Maru does not synthesize
  that digest today.
