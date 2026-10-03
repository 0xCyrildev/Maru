import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildClaim, type Claim } from "../src/envelope/claim.js";
import { MaruError } from "../src/lib/errors.js";
import { keyIdForJwk, privateKeyFromSeed, publicKeyOf, type Ed25519Jwk } from "../src/dsse/keys.js";
import { parseKeyring, type Keyring } from "../src/dsse/keyring.js";
import { signStatement } from "../src/dsse/sign.js";
import { verifyEnvelope } from "../src/dsse/verify.js";
import { toStatement } from "../src/envelope/statement.js";
import { compose, type CompositionResult } from "../src/ops/compose.js";
import { registryVersion } from "../src/registry/core.js";
import { checkChaseOverlap, runGates, type Fixture } from "./gates.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDENS = join(here, "goldens.json");

export interface ConformanceOutcome {
  ok: boolean;
  lines: string[];
}

/**
 * Conformance keys are derived from the tool id, so their seeds are public in this repository. That is
 * deliberate: they exist to make the sign → verify → compose path reproducible in CI, and a key whose
 * secret is committed can never be mistaken for a trust anchor. `maru key generate` is the only path to
 * a key anyone should rely on.
 */
function testKey(toolId: string): { keyId: string; jwk: Ed25519Jwk; privateKey: ReturnType<typeof privateKeyFromSeed> } {
  const seed = createHash("sha256").update(`maru/conformance-test-key/${toolId}`, "utf8").digest("hex");
  const privateKey = privateKeyFromSeed(seed);
  const jwk = publicKeyOf(privateKey);
  return { keyId: keyIdForJwk(jwk), jwk, privateKey };
}

function keyringFor(tools: string[]): Keyring {
  return parseKeyring({
    maruKeyring: "maru/keyring/v1",
    entries: [...new Set(tools)].sort().map((tool) => {
      const key = testKey(tool);
      return { toolId: tool, keyId: key.keyId, jwk: key.jwk, addedAt: "2026-10-02T00:00:00.000Z", note: "conformance test key — seed is public, therefore not a trust anchor" };
    })
  });
}

function claimFromFixture(fixture: Fixture, raw: Fixture["claims"][number]): Claim {
  return buildClaim({
    channel: raw.channel,
    predicate: raw.predicate,
    subjectKind: raw.subjectKind as never,
    subject: raw.subject,
    args: raw.args,
    value: raw.value,
    facet: raw.facet,
    lineageBasis: raw.basis,
    witness: raw.witness,
    provenance: raw.provenance as never,
    methodology: { tool: raw.tool, toolVersion: "conformance", check: raw.check, checkVersion: "1", emitter: raw.emitter as never },
    target: { kind: "transaction", network: String(raw.args.network ?? "mainnet"), digest: raw.args.digest ? String(raw.args.digest) : null },
    severitySignal: raw.severity as never,
    ...(raw.unverifiable ? { unverifiableFields: raw.unverifiable as never } : {}),
    ...(raw.evidence ? { evidence: raw.evidence } : {}),
    ...(fixture.registryMajor ? { registryMajor: fixture.registryMajor } : {}),
    emittedAt: "2026-10-02T00:00:00.000Z"
  });
}

const COUNTS: Record<string, (r: CompositionResult) => number> = {
  corroborate: (r) => r.corroborations.length,
  overlap: (r) => r.overlaps.length,
  contradict: (r) => r.contradictions.length,
  silent: (r) => r.silences.length,
  discharged: (r) => r.discharged.length,
  undischarged: (r) => r.undischarged.length,
  excluded: (r) => r.excluded.length,
  carried: (r) => r.carried.length,
  solitary: (r) => r.solitary.length,
  suppressed: (r) => r.suppressedCorroborations.length
};

function signalPair(a: string, b: string): number {
  const digest = "FrUvQrMgQ4wPqG4XqEPUW2aBp6rBPTQn2oXk1L8UvXc9";
  const make = (type: string): Claim =>
    buildClaim({
      channel: "assert",
      predicate: "move.finding.signal",
      subjectKind: "sui:transaction",
      subject: [digest],
      args: { network: "mainnet" },
      value: type,
      facet: `detector:${type}|${digest}`,
      lineageBasis: "derived",
      witness: "eligible",
      provenance: "deterministic",
      methodology: { tool: "chase", toolVersion: "0.3.0", check: type.toLowerCase(), checkVersion: "0.3.0", emitter: "dynamic-trace" },
      target: { kind: "transaction", network: "mainnet", digest },
      severitySignal: "medium",
      emittedAt: "2026-10-02T00:00:00.000Z"
    });
  return compose([make(a), make(b)]).corroborations.length;
}

export function runConformance(): ConformanceOutcome {
  const lines: string[] = [];
  const failures: string[] = [];
  const fixtures = (JSON.parse(readFileSync(join(here, "fixtures.json"), "utf8")) as { fixtures: Fixture[] }).fixtures;

  lines.push(`maru conformance — registry ${registryVersion()}, ${fixtures.length} fixture(s)`);

  const ring = keyringFor(fixtures.flatMap((f) => f.claims.map((c) => c.tool)));
  const results = new Map<string, CompositionResult>();
  const builtClaims = new Map<string, Claim[]>();
  const goldens: Record<string, string> = existsSync(GOLDENS) ? (JSON.parse(readFileSync(GOLDENS, "utf8")) as Record<string, string>) : {};
  const freshGoldens: Record<string, string> = {};
  const updateGoldens = process.env.MARU_UPDATE_GOLDENS === "1";

  for (const fixture of fixtures) {
    let claims: Claim[];
    try {
      claims = fixture.claims.map((raw) => claimFromFixture(fixture, raw));
    } catch (error) {
      const code = error instanceof MaruError ? error.code : "UNEXPECTED";
      if (fixture.expectRefuse === code) {
        lines.push(`  ok    ${fixture.id} — refused with ${code}`);
        continue;
      }
      if (fixture.expectRefuse) lines.push(`  FAIL  ${fixture.id} — expected refusal ${fixture.expectRefuse}, got ${code}: ${error instanceof Error ? error.message : ""}`);
      else lines.push(`  FAIL  ${fixture.id} — build refused unexpectedly: ${code}: ${error instanceof Error ? error.message : ""}`);
      failures.push(fixture.id);
      continue;
    }

    if (fixture.expectRefuse) {
      lines.push(`  FAIL  ${fixture.id} — expected refusal ${fixture.expectRefuse} and nothing was refused`);
      failures.push(fixture.id);
      continue;
    }

    let roundTripped: Claim[];
    try {
      roundTripped = claims.map((claim) => verifyEnvelope(signStatement(toStatement(claim), { keyId: testKey(claim.methodology.tool).keyId, privateKey: testKey(claim.methodology.tool).privateKey }), ring).claim);
    } catch (error) {
      lines.push(`  FAIL  ${fixture.id} — sign/verify: ${error instanceof Error ? error.message : String(error)}`);
      failures.push(fixture.id);
      continue;
    }

    const result = compose(roundTripped);
    const reversed = compose([...roundTripped].reverse());
    const stripTime = (r: CompositionResult): string => JSON.stringify({ ...r, generatedAt: "" });
    if (stripTime(result) !== stripTime(reversed)) {
      lines.push(`  FAIL  ${fixture.id} — composing the same claims in reverse order produced a different document`);
      failures.push(fixture.id);
    }

    fixture.claims.forEach((raw, i) => {
      const claim = roundTripped[i];
      if (!claim) return;
      const key = `${fixture.id}:${i}`;
      freshGoldens[key] = claim.claimId;
      const prior = goldens[key];
      if (!updateGoldens && prior && prior !== claim.claimId) {
        lines.push(`  FAIL  ${fixture.id}[${i}] — claimId drifted from the pinned golden (${prior.slice(0, 12)} → ${claim.claimId.slice(0, 12)}). A drifted identity reads exactly like a finding that vanished.`);
        failures.push(`${fixture.id}:golden`);
      }
      if (!updateGoldens && !prior) {
        lines.push(`  FAIL  ${fixture.id}[${i}] — no golden claimId pinned. Run MARU_UPDATE_GOLDENS=1 npm run conformance once, then review the diff.`);
        failures.push(`${fixture.id}:golden-missing`);
      }
    });

    if (!fixture.expect) {
      lines.push(`  FAIL  ${fixture.id} — no expectations`);
      failures.push(fixture.id);
      continue;
    }

    const mismatches: string[] = [];
    for (const [name, expected] of Object.entries(fixture.expect)) {
      const actual = COUNTS[name]?.(result);
      if (actual === undefined) {
        mismatches.push(`${name} (no such counter — a fixture asserting an undefined relation is a fixture that always passes)`);
        continue;
      }
      if (actual !== expected) mismatches.push(`${name} expected ${expected}, got ${actual}`);
    }
    if (mismatches.length > 0) {
      lines.push(`  FAIL  ${fixture.id}\n           ${mismatches.join("\n           ")}`);
      failures.push(fixture.id);
    } else {
      lines.push(`  ok    ${fixture.id} — ${Object.entries(fixture.expect).map(([k, v]) => `${k}=${v}`).join(" ")}`);
    }

    results.set(fixture.id, result);
    builtClaims.set(fixture.id, roundTripped);
  }

  if (updateGoldens) {
    writeFileSync(GOLDENS, `${JSON.stringify(Object.fromEntries(Object.entries(freshGoldens).sort()), null, 2)}\n`, "utf8");
    lines.push(`  goldens written: ${Object.keys(freshGoldens).length} claimId(s) pinned to ${resolve(GOLDENS)}`);
  }

  const gateFailures = runGates(fixtures, results, builtClaims);
  for (const gate of gateFailures) {
    lines.push(`  FAIL  gate ${gate.gate}: ${gate.detail}`);
    failures.push(`gate:${gate.gate}`);
  }
  lines.push(`  static gates: ${gateFailures.length === 0 ? "all passed" : `${gateFailures.length} failed`}`);

  const overlap = checkChaseOverlap(process.env.CHASE_SRC, signalPair);
  for (const line of overlap.lines) lines.push(`  ${overlap.ran ? "info" : "WARN"} ${line}`);
  for (const gate of overlap.failures) {
    lines.push(`  FAIL  gate ${gate.gate}: ${gate.detail}`);
    failures.push(`gate:${gate.gate}`);
  }

  lines.push(failures.length === 0 ? `\nCONFORMANCE PASS — ${fixtures.length} fixture(s), no gate failures` : `\nCONFORMANCE FAIL — ${failures.length} problem(s): ${[...new Set(failures)].join(", ")}`);
  return { ok: failures.length === 0, lines };
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split("/").pop() ?? "")) {
  const outcome = runConformance();
  for (const line of outcome.lines) console.log(line);
  process.exit(outcome.ok ? 0 : 1);
}
