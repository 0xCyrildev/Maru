# Fixture provenance

These files are not Maru's own work product; they are copied so that `npm test` passes in a fresh clone
on a machine with no other checkout present. A fixture that only exists on one laptop is not a test.

- `synthetic-leak/` and `clean-order.{trace,report}.json` — from [0xCyrildev/Chase](https://github.com/0xCyrildev/Chase) (MIT),
  `test-cases/synthetic-leak/` and `test-cases/fixtures/`. The synthetic Move package is the corpus Chase's
  own positive controls are built from.
- `leak-mut.{trace,report}.json` — the trace at `test-cases/fixtures/testnet/9gwFpqxG….json` (Chase, MIT),
  plus the report produced by **running Chase's 11 real invariant checkers over it** via
  `scripts/extract-chase-fixture.ts`. Regenerate rather than hand-edit:

  ```bash
  CHASE_SRC=~/projects/chase npx tsx scripts/extract-chase-fixture.ts \
    "$CHASE_SRC/test-cases/fixtures/testnet/9gwFpqxGmnfUyu8ciiEHHKHmWw42vMJddD6PpUuGLkKg.json" \
    test/fixtures/leak-mut.report.json testnet
  ```

The package id `0x10172126…f12405` appears in these fixtures because it is a published testnet id that
Chase's own trace records — it is on-chain public data, not a secret. The seeds behind every conformance
signing key are derived from tool ids and are therefore public by design; see
`docs/spec/03-trust-and-adoption.md` for why those keys are not trust anchors.
