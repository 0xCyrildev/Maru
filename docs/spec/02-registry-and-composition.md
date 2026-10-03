# Registry and composition rules

## `core@1` — a closed predicate registry

An assumption is not prose. It is `{predicate, subject, args, value}` drawn from this table, so two tools
collide deterministically on a declared identity instead of a model guessing whether two English sentences
conflict. What is not here cannot be assumed, determined or collided — and the absence is reported as
*incomparability*, never as agreement.

| Predicate | Subject | Args | Domain | Mode | Group | May assert |
|---|---|---|---|---|---|---|
| `move.object.ownership` | sui:object | network | address · consensus-address · object · shared · immutable | exclusive | — | dynamic-trace |
| `move.object.change` | sui:object | network, digest | created · mutated · deleted · absent · **multiple** | exclusive | — | dynamic-trace |
| `move.dynamicField.lifecycle` | sui:object | network, digest, keyType | created · deleted · **cycle** · absent | exclusive | — | dynamic-trace |
| `move.event.presence` | sui:package-module | network, digest | present · absent | exclusive | — | **dynamic-trace only** |
| `move.ref.return.observed` | sui:function | network, digest | mutable · immutable | exclusive | `move.ref.return` | dynamic-trace |
| `move.ref.return.declared` | sui:function | package | mutable · immutable | exclusive | `move.ref.return` | static-source |
| `move.balance.delta` | sui:address-coin | network, digest | (open, signeddecimal) | distinct | — | dynamic-trace |
| `move.ptb.calls` | sui:package-module | network, digest | (open, csvsorted) | distinct | — | dynamic-trace |
| `move.function.signature` | sui:function | package | (open, uri) | distinct | — | static-source |
| `move.value.control` | sui:function | package | caller · internal | exclusive | — | **static-source only** |
| `move.finding.signal` | sui:transaction | network | (open, token) | — | **outside the algebra** | any |

Three choices in this table carry the design:

- **`assertEmitters` gives `silent` its direction.** A source reader may assume what only a trace can
  determine (`move.event.presence`), and a trace may not assert what only source can determine
  (`move.value.control`). So a static guess can be falsified by a measured fact and never the reverse.
- **`multiple` and `cycle` exist so a disagreement is stated instead of resolved.** An object reported with
  two change types is `multiple`, not a coin flip. A field created *and* deleted in one transaction is
  `cycle`, because teardown-and-replace is one construct — two assertions there would manufacture a
  contradiction out of an ordinary PTB.
- **`move.finding.signal` is non-collidable.** A detector firing is a fact about the tool. Left in the
  algebra, three labels on one transaction would become three opinions, and two different labels would
  become a contradiction about the transaction.

`unresolved` and `unrecorded` are **not values anywhere**. They are coverage records
(`not-read` = nobody looked, `ambiguous` = looked and could not classify), because a domain token that
means "no determination was made" would let a reader take silence for evidence of absence.

## Conflict spaces

Two claims collide only when they share a subject **and** the registry declares a space they both speak in:
the same predicate, or two predicates of one `conflictGroup`. `exclusive` and `distinct` both decide
"different ⇒ incompatible"; they differ in whether the domain is closed, which matters to readers and to
`UNKNOWN_VALUE`, not to the decision.

A cross-predicate group may join claims of different *scope* — "observed mutable in this transaction"
against "declared mutable in this package". That is deliberate: such a pair is a **dispute for a human**,
which is what `contradict` means. The protocol never resolves it.

## Lineage: facets, not names

`overlap` versus `corroborate` turns on one question — same construct, or second opinion? The answer is a
**facet** the emitter supplies, hashed into `lineage.key`.

The Chase adapter keys facets on the *trace field a claim was read from*, not the detector that read it:
`trace:object-changes|<objectId>`, `trace:resolved-signature|<function>`, `rpc:readEffects|…`. So two
detectors that both read `objectChanges` are one opinion, and a trace plus a source reader are two.

Consequence, stated plainly: **Chase's `EXPECTED_OVERLAP` table has nothing to suppress here.** Its eleven
pairs are signal claims, and signals are outside the algebra by registry rule. The conformance suite reads
that table out of Chase's own source when present and asserts no pair ever yields a corroboration —
"a typo here silently re-enables corroboration inflation", generalized.

And equally plainly: no generalizable lineage key exists for the pattern cluster, because its evidence
carries indices rather than object identity. Those claims are carried, not composed. The alternative — a
hand-declared facet table for them — would be a claim that a table was derived when it was written.

## Composition output

```
corroborations[]         topic, subject, opinions[{lineageKey, facet, basis, claimIds[], tools[], provenances[]}]
overlaps[]               topic, one lineage key, ≥2 distinct claimIds
solitary[]               one opinion on one topic — seen, compared, nothing to say
contradictions[]         space, values, left/right oriented by claimId, nextAction: "human-review"
silences[]               the assumption (falsified) and the assertion that falsified it
discharged[]             assumption confirmed by a determination
undischarged[]           assumption nobody addressed, with the reason why
suppressedCorroborations[] topics that would have corroborated except that a claim in them is disputed
excluded[]               claim, reason (assumption / report-only / partial / model|fallback / imported)
carried[]                claims on non-collidable predicates
coverage[]               skipped · not-read · ambiguous · detector-error · empty-run · range-incomplete
inputs[]                 the exact claimIds composed
headline                 one line that refuses to imply more than the lists say
```

**No `score`, no `tier`, no merged severity, at any depth.** A gate walks the result and fails on any key
matching `/score|tier|priority|weight|rank|confidence|severity|escalat.*/i`. Witnesses are a list; nothing
numeric is counted into an escalation.

**A dispute blocks escalation.** `suppressContradicted` removes any topic whose opinions include a disputed
claim, so two claims that cannot both hold are never counted as two opinions. The suppression is reported,
not silent.

**A composition result is not a claim.** It is a signed statement with
`predicateType: .../composition/v1`, whose subject is the digest of its input claimIds. It has no registry
predicate, so it cannot enter a join — not a depth rule, a type that cannot be an input.

## Determinism

Input order must not change a byte of the output. Every list needs a *total* order: contradiction pairs are
oriented by claimId, opinions by lineage key, excluded by claimId+reason, coverage by kind+subject. The
suite asserts `compose(x) === compose(reverse(x))` modulo `generatedAt`, and `conformance` re-asserts it
per fixture — the first version of this got the ordering of a contradiction pair wrong and reported the
same dispute two different ways.
