# Maru

**A signed claim format and composition algebra for Web3 security tooling.**

A finding stops being a line of text and becomes an attributable claim with a named methodology,
explicit assumptions whose subject another tool can check, and a stated limit. Two tools that looked at
the same transaction can then be composed: they corroborate, they overlap, they contradict, or one of
them turns out to have assumed something the other determined to be false.

It is not a scanner. It does not inspect anything. It is the layer that lets the ~90 tools on
[pashov/ai-web3-security](https://github.com/pashov/ai-web3-security) say what they mean to each other,
so an agent consuming several of them does not re-invent reconciliation for every pair.

## Why not SARIF, which already exists

Because SARIF carries **assertions and no assumptions**. A `result` has a rule id, a location, a level,
and `partialFingerprints` for heuristic identity. It has no machine-decidable precondition, no complement
relation between two tools' values, and no way to say "this finding holds only if the mutated value was
not already in the caller's hands". VEX reconciles a known CVE against a status; in-toto attests a
provenance. None of them can express the case that started this project:

> Chase reports `MUTABLE_REFERENCE_RETURNED` on `leak::leak_mut`, which is true — the resolved signature
> returned a mutable reference and the transaction reverted trying to use it. Whether that escape matters
> depends on **who controls the value**, and that is a Move-source question. No further Chase run can
> answer it.

Maru answers it by making the premise explicit and checkable. A source reader determines that
`leak_mut(vault: &mut Vault)` receives its mutable handle from the caller. The premise is falsified, the
finding is **silenced**, and it is reported as silenced rather than quietly dropped:

```
SILENT — an assumption falsified by a determination
  sui:function:0x1017…12405|leak|leak_mut
      chase assumed internal; move-static determined caller
      The dynamic-trace reading assumed "internal" …; the static-source reading determined "caller".
      The finding rests on a premise another tool falsified.

CORROBORATE — independent opinions
  move.ref.return|sui:function:0x1017…12405|leak|leak_mut
      · chase via 70200e39f72b
      · move-static via 73d7e55de160
```

Maru ships *inside* the existing plumbing rather than beside it: a claim is an in-toto v1 Statement in a
DSSE envelope (`DSSEv1` PAE over the exact payload bytes, Ed25519), with one new `predicateType`. SARIF
2.1.0 import and export are implemented — and `import` refuses a foreign file-and-region result rather
than inventing a subject for it, because conversion is not composition.

## Install and run

```bash
npm i -g @zeroxcyril/maru     # or: npx -y -p @zeroxcyril/maru maru <cmd>

maru registry                                  # what may be asserted, assumed, collided
maru key generate --tool chase                 # a signing key + a pinned keyring entry
maru emit chase --report analysis.json --trace trace.json --key keys/chase.pem -o chase.maru.json
maru emit move-static --sources ./sources --network testnet \
      --address chase_test=0x1017…12405 --digest <tx> --key keys/move-static.pem -o static.maru.json
maru compose chase.maru.json static.maru.json
maru verify chase.maru.json                    # attributable and self-consistent; never "correct"
maru sarif export chase.maru.json -o chase.sarif.json
```

`emit` without `--key` prints an unsigned preview and writes **no file**. An unsigned document must not
look like an interchange format.

## The four relations are two procedures

`corroborate` and `overlap` are one join that differs by a lineage boolean. `contradict` and `silent` are
one collision whose label is chosen by which side is asserting. Say it plainly rather than implying four
machines:

| Relation | Decided by |
|---|---|
| **corroborate** | same conflict space + same subject, **distinct** lineage keys, both witness-eligible |
| **overlap** | same space + same subject, **equal** lineage keys — one construct, one opinion |
| **contradict** | same subject, values the registry declares incompatible, **both asserting** → `human-review`, and it blocks both from escalating |
| **silent** | same subject, incompatible values, **one asserts and one assumed** → the assumption is falsified |

Plus four outputs that are not silence: `discharged`, `undischarged`, `solitary`, `refused-with-reason`.
A non-collision is *not* agreement, and the report never lets it read that way.

## What v0 is not, and the cost of each omission

- **~4 of Chase's 12 violation types can enter the algebra.** Only claims carrying object, address,
  function or module identity have a subject to collide on. The pattern cluster — `FLASH_LOAN_SHAPED`,
  `REENTRANCY_PATTERN`, `REPEATED_MODULE_CALLS` — shares no subject at all, so there is **no derivable
  lineage key** for it. Their labels are carried, never composed. Published as a limit, not negotiated.
- **No reputation.** A tool's track record needs review data nobody has yet. `confidence` is a
  provenance ladder (`deterministic › rules › model › fallback`), not a score.
- **No key rotation or revocation.** `maru key drop` stops future attribution; every claim an old key
  signed still verifies. A compromised key is bounded only by you re-checking what you relied on.
- **Model-provenance claims never witness.** The channel that asserted is the channel under test. This is
  the honest adoption ceiling: the LLM audit *skills* next to Chase on that list can emit assumptions and
  limits, and contribute nothing to corroboration.
- **Sui only, one network per claim.** The registry's namespaces are Move-shaped; EVM needs its own.
- **The registry is hand-curated.** Its absences are invisible by nature, so `contradict` will fire
  rarely at first and reviewers may read the quiet as consensus.

## Composition cannot raise anything

There is no `score`, no `tier` and no merged `severity` anywhere in a composition result — a conformance
gate walks the output and fails on any key matching `/score|tier|priority|weight|rank|confidence|severity/`.
Witnesses are returned as a **list of opinions**, not a count. A composition result is not a claim, so it
cannot be fed back in; and a dispute blocks escalation instead of doubling as corroboration.

Downstream triage can still misbehave, and the protocol cannot police it. That is a real limit, not a
solvable one.

## Development

```bash
npm run typecheck    # tsc -p tsconfig.check.json — src + scripts + conformance + test, noEmit
npm run build        # clean dist, compile, mark bins executable
npm test             # 31 checks: identity, DSSE, refusals, adapters, all four relations, SARIF
npm run conformance  # 19 fixtures (must-fire and must-not-fire per relation) + static gates + goldens
CHASE_SRC=~/projects/chase npm run conformance   # also diffs the detector table against Chase's source
```

`conformance/goldens.json` pins every fixture `claimId`. Change an encoder and the suite fails with
"claimId drifted", which is the only thing that separates *a finding was renumbered* from *a finding
disappeared*.

Spec: [`docs/spec/`](docs/spec). License: MIT.
