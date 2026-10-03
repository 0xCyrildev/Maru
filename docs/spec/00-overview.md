# Maru specification — overview

Status: v0, `@zeroxcyril/maru@0.0.1`, registry `core@1`. Everything here is implemented; nothing in here
is a plan. Where the implementation is deliberately weak, that is stated in the same section as the feature.

## 1. Problem

Security tools emit findings in isolation. An agent using several must decide, per pair, whether two
findings describe one construct, two independent observations, or a disagreement — and then re-decide it
for the next tool. Nothing in the existing interchange formats carries the information that decision
needs, because none of them models a *precondition*.

## 2. Position

Maru is a claim format plus a composition algebra. It does not analyze, rank or decide anything.

It ships inside the plumbing that already exists:

| Layer | Maru uses | Maru adds |
|---|---|---|
| statement | in-toto v1 `Statement` (`_type`, `subject`, `predicateType`, `predicate`) | one `predicateType`: `https://maru.dev/predicate/finding/v1` |
| signature | DSSE `PAEv1` over the exact payload bytes, Ed25519 | a pinned local keyring, no PKI |
| finding interchange | SARIF 2.1.0 import/export | a subject namespace for on-chain identities |
| status interchange | — | VEX has no object-identity model for chain state; not used |

The URIs are identifiers, not websites. v0 publishes no registry site and does not imply one.

## 3. Two procedures, four names

Claims are projected to `(predicateId, normalizedSubject, args, value, channel)` where
`channel ∈ assert | assume`. Composition is:

- **`join`** — group assertions by *topic* (conflict space + subject), collapse to one opinion per distinct
  lineage key. ≥2 opinions → `corroborate` (a list of opinions). 1 opinion, ≥2 claims → `overlap`. 1
  opinion, 1 claim → `solitary`.
- **`collision`** — compare a pair sharing a subject and a declared conflict space, using the registry's
  complement relation. Both assert and values incompatible → `contradict` (→ `human-review`, and it
  suppresses that topic's corroboration). One asserts, one assumed, incompatible → `silent` (the
  assumption is falsified). One asserts, one assumed, equal → `discharged`. Assumption with nothing
  asserting → `undischarged`.

`overlap` is lineage *equality*; `corroborate` is lineage *inequality*. `contradict` is two assertions;
`silent` is one assertion against one assumption. There are not four mechanisms.

## 4. Naming collision to avoid

Chase's `silent-object-change` means "state changed with no event". Maru's `silent` means "an assumption
was falsified". In Maru documents Chase's concept is always written **unannounced**.

## 5. Non-goals in v0, with the risk bought

No reputation or track-record scoring (no review data exists yet). No dispute workflow beyond emitting a
`Contradiction` record (an ignored record reads as protocol silence). No key rotation or revocation (a
compromised key signs forever; mitigation is that `verify` is auditable). No multi-chain namespaces. No
MCP surface. No canonical JSON of arbitrary evidence. No numeric field of any kind in a composition result.

## 6. Known weak points, stated for reviewers

1. **Coverage is narrow by construction.** Only claims with object, address, function, module or
   transaction identity have a subject. For Chase that is roughly 4 of 12 violation types; the pattern
   cluster cannot enter the join at all, and no generalizable lineage key exists in its evidence.
2. **The registry is curated.** A predicate that is not declared cannot be assumed or determined, so its
   absence is invisible and `contradict` will fire rarely. The mitigation is that non-collision is a
   reported state, never agreement.
3. **Composition has no teeth downstream.** Structural rules (no `score`, witnesses as a list, results
   that are not claims, dispute-blocks-escalation) bind implementations that obey them. A consumer that
   counts opinions and escalates anyway is outside Maru's reach.
