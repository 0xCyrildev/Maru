import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CONFLICT_GROUPS, PREDICATES, lookupPredicate, registryVersion } from "../src/registry/core.js";
import type { Claim } from "../src/envelope/claim.js";
import type { CompositionResult } from "../src/ops/compose.js";
import { driftCheck, EMISSIONS } from "../src/adapters/chase/methodology.js";

export interface FixtureClaim {
  tool: string;
  check: string;
  emitter: string;
  channel: "assert" | "assume";
  predicate: string;
  subjectKind: string;
  subject: string[];
  args: Record<string, unknown>;
  value: unknown;
  facet: string;
  basis: "derived" | "declared";
  witness: "eligible" | "report-only";
  provenance: string;
  severity: string;
  unverifiable?: { field: string; reason: string }[];
  evidence?: Record<string, string>;
}

export interface Fixture {
  id: string;
  note?: string;
  registryMajor?: number;
  expectRefuse?: string;
  expect?: Record<string, number>;
  claims: FixtureClaim[];
}

const ESCALATION_KEY = /^(score|tier|priority|weight|rank|confidence|severity|escalat\w*)$/i;
/** These belong to the coverage channel. A value in a domain that means "nobody looked" is the collapse Maru forbids. */
const COVERAGE_ONLY_TOKENS = new Set(["unresolved", "unrecorded", "unknown", "none", "n/a", "null"]);

function keysAtDepth(value: unknown, into: Set<string>): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) keysAtDepth(item, into);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      into.add(key);
      keysAtDepth(child, into);
    }
  }
  return into;
}

export interface GateFailure {
  gate: string;
  detail: string;
}

/**
 * Static gates over the registry and the fixtures — the protocol-wide version of the check Chase calls
 * "a typo here silently re-enables corroboration inflation". These run before any composition, because a
 * fixture that names a predicate that does not exist is not a failing test, it is a test of nothing.
 */
export function runGates(fixtures: Fixture[], results: Map<string, CompositionResult>, claims: Map<string, Claim[]>): GateFailure[] {
  const failures: GateFailure[] = [];
  const byId = new Map(PREDICATES.map((p) => [p.id, p]));

  for (const fixture of fixtures) {
    // A refusal fixture deliberately names something invalid; that is the test. The structural gates
    // still read it, so the skip cannot hide a mistyped expectation.
    const expectBuildRefusal = Boolean(fixture.expectRefuse);
    for (const claim of fixture.claims) {
      const def = byId.get(claim.predicate);
      if (!def) {
        if (!expectBuildRefusal) {
          failures.push({ gate: "predicate-exists", detail: `${fixture.id}: predicate "${claim.predicate}" is not in ${registryVersion()}. A typo here silently disables the rule this fixture is supposed to prove.` });
        }
        continue;
      }
      if (def.subjectKind !== claim.subjectKind && !expectBuildRefusal) {
        failures.push({ gate: "subject-kind", detail: `${fixture.id}: "${claim.predicate}" is about ${def.subjectKind}, the fixture files it under ${claim.subjectKind}.` });
      }
      if (typeof claim.value === "string" && COVERAGE_ONLY_TOKENS.has(claim.value.toLowerCase()) && !expectBuildRefusal) {
        failures.push({ gate: "coverage-not-a-value", detail: `${fixture.id}: value "${claim.value}" belongs in the coverage channel, not in a predicate domain.` });
      }
      if (!def.emitters.includes(claim.emitter as never) && !expectBuildRefusal) {
        failures.push({ gate: "emitter-permitted", detail: `${fixture.id}: ${claim.emitter} may not speak "${claim.predicate}". If this fixture means to prove a refusal, set expectRefuse.` });
      }
    }
  }

  const referenced = new Set(fixtures.flatMap((f) => f.claims.map((c) => c.predicate)));
  for (const def of PREDICATES) {
    if (!referenced.has(def.id)) {
      failures.push({ gate: "registry-covered", detail: `${def.id} is declared in ${registryVersion()} and appears in no fixture. An unexercised predicate is an untested complement relation.` });
    }
  }

  for (const group of CONFLICT_GROUPS) {
    for (const predicate of group.predicates) {
      try {
        lookupPredicate(predicate);
      } catch {
        failures.push({ gate: "conflict-group-names", detail: `conflict group ${group.id} names "${predicate}", which the registry does not declare.` });
      }
    }
    const distinct = new Set(group.predicates);
    if (distinct.size < 2) {
      failures.push({ gate: "conflict-group-purpose", detail: `conflict group ${group.id} lists ${distinct.size} predicate(s); a group of one can never collide across tools.` });
    }
  }

  for (const [id, result] of results) {
    const topics = new Set(result.corroborations.map((c) => c.topic));
    for (const contradiction of result.contradictions) {
      const asTopic = `${contradiction.space}|${contradiction.subjectUri}`;
      if (topics.has(asTopic)) {
        failures.push({ gate: "dispute-blocks-escalation", detail: `${id}: topic ${asTopic} is both corroborated and contradicted. Two opinions that cannot both hold are not two opinions.` });
      }
    }
    const banned = [...keysAtDepth(result, new Set<string>())].filter((k) => ESCALATION_KEY.test(k));
    if (banned.length > 0) {
      failures.push({ gate: "no-escalation-field", detail: `${id}: composition output carries ${banned.join(", ")}, which a consumer could count into a verdict.` });
    }
    const carriedClaims = claims.get(id) ?? [];
    for (const corroboration of result.corroborations) {
      // Corroboration means *distinct lineages*. Assert that directly: an earlier version of this gate
      // tested `opinions.length < 2` inside a list that only ever holds two or more, so it could never
      // fail and reported confidence it had never earned.
      const distinct = new Set(corroboration.opinions.map((o) => o.lineageKey));
      if (distinct.size !== corroboration.opinions.length) {
        failures.push({ gate: "corroboration-needs-distinct-lineage", detail: `${id}: ${corroboration.topic} repeats a lineage key across opinions, so it is not two independent opinions.` });
      }
      if (distinct.size < 2) {
        failures.push({ gate: "corroboration-needs-distinct-lineage", detail: `${id}: ${corroboration.topic} reports corroboration from ${distinct.size} distinct lineage(s).` });
      }
    }
    for (const overlap of result.overlaps) {
      if (overlap.claimIds.length < 2) {
        failures.push({ gate: "overlap-needs-two-claims", detail: `${id}: overlap on ${overlap.topic} lists ${overlap.claimIds.length} claim(s) — one claim is solitary, not an overlap.` });
      }
    }
    for (const excluded of result.excluded) {
      const claim = carriedClaims.find((c) => c.claimId === excluded.claimId);
      if (claim && claim.witness === "eligible" && (claim.verifiability !== "full" || claim.channel !== "assert")) {
        failures.push({ gate: "exclusion-is-explained", detail: `${id}: ${excluded.claimId.slice(0, 12)} still carries witness:"eligible" yet was excluded as ${excluded.reason}; the downgrade in buildClaim() stopped being applied.` });
      }
      if (excluded.declaredWitness === "eligible" && claim && claim.witness === "eligible" && claim.channel === "assert" && claim.verifiability === "full") {
        failures.push({ gate: "exclusion-is-explained", detail: `${id}: ${excluded.claimId.slice(0, 12)} was excluded while still looking eligible — reason "${excluded.reason}".` });
      }
    }
  }

  return failures;
}

export interface ChaseTableReport {
  ran: boolean;
  lines: string[];
  failures: GateFailure[];
}

/**
 * Chase's own measured overlap table, used as an external check rather than a paraphrase: every pair it
 * calls "the same construct" must still produce no corroboration once it reaches Maru, because in Maru
 * those pairs are signal claims and signals are outside the algebra by registry rule. If that ever stops
 * being true, the table has been smuggled back in through the join.
 */
export function checkChaseOverlap(chaseSourceDir: string | undefined, composePair: (a: string, b: string) => number): ChaseTableReport {
  if (!chaseSourceDir || !existsSync(join(chaseSourceDir, "src/triage/enrich.ts"))) {
    return { ran: false, lines: ["chase overlap table NOT RUN — no Chase source tree available; the claim that signals cannot inflate corroboration is untested against the real table."], failures: [] };
  }
  const source = readFileSync(join(chaseSourceDir, "src/triage/enrich.ts"), "utf8");
  const pairs = [...source.matchAll(/\[\s*"([A-Z_]+)"\s*,\s*"([A-Z_]+)"\s*\]/g)].map((m) => [m[1] as string, m[2] as string]);
  const failures: GateFailure[] = [];
  const lines: string[] = [`chase overlap table: read ${pairs.length} declared pair(s) from ${chaseSourceDir}`];
  for (const [a, b] of pairs) {
    if (!a || !b || !EMISSIONS[a] || !EMISSIONS[b]) {
      failures.push({ gate: "overlap-pair-known", detail: `EXPECTED_OVERLAP names ${String(a)}/${String(b)}, which the adapter's emission table does not know.` });
      continue;
    }
    const corroborations = composePair(a, b);
    if (corroborations !== 0) {
      failures.push({ gate: "overlap-never-corroborates", detail: `${a} + ${b} produced ${corroborations} corroboration(s). Chase declares them one construct; a join that counts them twice is the inflation this protocol exists to stop.` });
    }
  }
  const drift = driftCheck(chaseSourceDir);
  if (!drift.checked) lines.push(`detector table drift check NOT RUN — ${drift.reason}`);
  else if (drift.differences.length > 0) failures.push({ gate: "detector-table-drift", detail: drift.differences.join(" ") });
  else lines.push("detector table drift check: clean");
  return { ran: true, lines, failures };
}
