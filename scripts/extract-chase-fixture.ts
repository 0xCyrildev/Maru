/**
 * Regenerates a committed conformance fixture by running Chase's own invariant checkers over a trace
 * Chase already ships as a fixture. Nothing here modifies Chase or adds it as a dependency: the path is
 * read from the environment, and the output is a plain AnalysisReport JSON, which is exactly what
 * `chase analyze --json` writes.
 *
 * The point is provenance. A fixture that was *typed by hand* tests the adapter's imagination; a fixture
 * produced by the detectors themselves tests the adapter against what Chase actually emits.
 *
 *   CHASE_SRC=~/projects/chase npx tsx scripts/extract-chase-fixture.ts <trace.json> <out.json> <network>
 */
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const [tracePath, outPath, networkArg] = process.argv.slice(2);
if (!tracePath || !outPath || !networkArg) {
  console.error("usage: extract-chase-fixture.ts <trace.json> <out.json> <network>");
  process.exit(2);
}

const chaseSrc = process.env.CHASE_SRC;
if (!chaseSrc) {
  console.error("CHASE_SRC is not set. Refusing to run: the fixture must come from a named Chase source tree, not from a path guessed at.");
  process.exit(2);
}

const invariants = await import(`${resolve(chaseSrc, "src/invariants/index.ts")}`);
const trace = JSON.parse(readFileSync(tracePath, "utf8"));
const violations: unknown[] = [];
const detectorErrors: string[] = [];

for (const checker of invariants.allInvariants) {
  try {
    violations.push(...checker.check(trace));
  } catch (error) {
    detectorErrors.push(`${checker.name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

writeFileSync(
  outPath,
  `${JSON.stringify(
    {
      digest: trace.digest,
      network: networkArg,
      timestamp: trace.timestamp ?? "",
      sender: trace.sender,
      success: trace.success,
      violations,
      detectorErrors,
      stats: {
        balanceChanges: (trace.balanceChanges ?? []).length,
        objectChanges: (trace.objectChanges ?? []).length,
        ptbCommands: (trace.ptbCommands ?? []).length,
        events: (trace.events ?? []).length,
        silentObjectChanges: 0
      }
    },
    null,
    2
  )}\n`
);

console.log(`${outPath}: ${violations.length} violation(s) from ${invariants.allInvariants.length} checker(s), ${detectorErrors.length} detector error(s)`);
for (const v of violations as { type: string; severity: string }[]) console.log(`  - ${v.type} @ ${v.severity}`);
