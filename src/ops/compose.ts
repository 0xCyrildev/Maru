import { createHash } from "node:crypto";
import type { Claim } from "../envelope/claim.js";
import type { CoverageRecord } from "../envelope/coverage.js";
import { coverageHeadline } from "../envelope/coverage.js";
import { COMPOSITION_PREDICATE_TYPE, STATEMENT_TYPE, type InTotoStatement } from "../envelope/statement.js";
import { REGISTRY_MAJOR, isCollidable, lookupPredicate } from "../registry/core.js";
import { collide, type Contradiction, type Discharged, type Silence, type Undischarged } from "./collision.js";
import { join, type Corroboration, type Overlap } from "./join.js";
import { partition, type ExcludedClaim } from "./refuse.js";

export const ENGINE = { name: "@zeroxcyril/maru", version: "0.0.1" } as const;

export interface CompositionResult {
  maru: "maru/composition/v1";
  engine: typeof ENGINE;
  registryMajor: number;
  generatedAt: string;
  /** The exact set of claims this result was computed from. Nothing else can be inferred from a report. */
  inputs: string[];
  corroborations: Corroboration[];
  overlaps: Overlap[];
  solitary: { topic: string; subjectUri: string; claimIds: string[] }[];
  contradictions: Contradiction[];
  silences: Silence[];
  discharged: Discharged[];
  undischarged: Undischarged[];
  /**
   * Topics that would have corroborated except that one of their assertions is part of a contradiction.
   * A dispute blocks escalation; it does not quietly disappear into "agreement".
   */
  suppressedCorroborations: SuppressedCorroboration[];
  excluded: ExcludedClaim[];
  /**
   * Claims on predicates the registry marks non-collidable — signal-shaped claims about a detector
   * firing. They are carried through untouched and enter no topic, because "two detectors gave
   * different labels for the same transaction" is not a contradiction about the transaction.
   */
  carried: { claimId: string; predicate: string; value: string }[];
  coverage: CoverageRecord[];
  headline: string;
}

function sortedIds(claims: readonly Claim[]): string[] {
  return [...new Set(claims.map((c) => c.claimId))].sort();
}

export interface SuppressedCorroboration {
  topic: string;
  subjectUri: string;
  claimIds: string[];
  reason: string;
}

/**
 * A contradiction blocks escalation. Without this step a pair of claims that cannot both hold would be
 * counted twice over: once as a dispute, and again as two independent opinions — which is exactly the
 * "corroboration inflation" Chase's own overlap table exists to prevent, reintroduced through the back
 * door of a join that never looks at collisions.
 */
function suppressContradicted(
  corroborations: Corroboration[],
  contradictions: Contradiction[]
): { kept: Corroboration[]; suppressed: SuppressedCorroboration[]; demoted: { topic: string; subjectUri: string; claimIds: string[] }[] } {
  const disputed = new Set<string>();
  for (const contradiction of contradictions) {
    disputed.add(contradiction.left.claimId);
    disputed.add(contradiction.right.claimId);
  }

  const kept: Corroboration[] = [];
  const suppressed: SuppressedCorroboration[] = [];
  const demoted: { topic: string; subjectUri: string; claimIds: string[] }[] = [];

  for (const corroboration of corroborations) {
    const tainted = corroboration.opinions.filter((o) => o.claimIds.some((id) => disputed.has(id)));
    if (tainted.length === 0) {
      kept.push(corroboration);
      continue;
    }
    const clean = corroboration.opinions.filter((o) => !tainted.includes(o));
    suppressed.push({
      topic: corroboration.topic,
      subjectUri: corroboration.subjectUri,
      claimIds: tainted.flatMap((o) => o.claimIds).sort(),
      reason: "An assertion in this topic is part of a contradiction, so the topic contributes no corroboration until a human resolves it."
    });
    if (clean.length >= 2) kept.push({ ...corroboration, opinions: clean });
    else demoted.push({ topic: corroboration.topic, subjectUri: corroboration.subjectUri, claimIds: corroboration.opinions.flatMap((o) => o.claimIds).sort() });
  }

  return { kept, suppressed, demoted };
}

/**
 * What the claims say about one subject, using only assertions strong enough to determine anything.
 *
 * An assertion that is not witness-eligible cannot silence or contradict: a claim whose subject cannot
 * be pinned, or whose channel is the model under test, is not evidence about the world. It is still
 * reported — in `excluded`, with the reason — so a reader sees what was left out rather than inferring
 * that nobody said it.
 */
export function compose(claims: readonly Claim[], coverage: readonly CoverageRecord[] = []): CompositionResult {
  const composable: Claim[] = [];
  const carried: { claimId: string; predicate: string; value: string }[] = [];
  for (const claim of claims) {
    if (isCollidable(lookupPredicate(claim.predicate, claim.registryMajor))) composable.push(claim);
    else carried.push({ claimId: claim.claimId, predicate: claim.predicate, value: claim.value });
  }
  carried.sort((a, b) => a.claimId.localeCompare(b.claimId));

  const { witnesses, excluded } = partition(composable);
  const assumptions = composable.filter((c) => c.channel === "assume");
  const joined = join(witnesses);
  const collided = collide([...witnesses, ...assumptions]);
  const suppressedJoin = suppressContradicted(joined.corroborations, collided.contradictions);

  // Every list here needs a *total* order. Sorting on one key with ties left in input order is how a
  // report stops being reproducible between two runs over the same claims.
  const byTopicThenClaims = <T extends { topic: string; subjectUri: string }>(x: T, y: T, ids: (v: T) => string[]) =>
    x.topic.localeCompare(y.topic) || x.subjectUri.localeCompare(y.subjectUri) || ids(x).join(",").localeCompare(ids(y).join(","));

  return {
    maru: "maru/composition/v1",
    engine: ENGINE,
    registryMajor: REGISTRY_MAJOR,
    generatedAt: new Date().toISOString(),
    inputs: sortedIds(claims),
    corroborations: suppressedJoin.kept.sort((a, b) => byTopicThenClaims(a, b, (v) => v.opinions.flatMap((o) => o.claimIds))),
    overlaps: joined.overlaps.sort((a, b) => byTopicThenClaims(a, b, (v) => v.claimIds)),
    solitary: [...joined.solitary, ...suppressedJoin.demoted]
      .map((s) => ({ ...s, claimIds: [...s.claimIds].sort() }))
      .sort((a, b) => byTopicThenClaims(a, b, (v) => v.claimIds)),
    contradictions: collided.contradictions,
    silences: collided.silences,
    discharged: collided.discharged,
    undischarged: collided.undischarged,
    suppressedCorroborations: suppressedJoin.suppressed
      .map((s) => ({ ...s, claimIds: [...s.claimIds].sort() }))
      .sort((a, b) => a.topic.localeCompare(b.topic) || a.claimIds.join(",").localeCompare(b.claimIds.join(","))),
    excluded: excluded.sort((a, b) => a.claimId.localeCompare(b.claimId) || a.reason.localeCompare(b.reason)),
    carried,
    coverage: [...coverage].sort((a, b) => `${a.kind}|${a.subject}`.localeCompare(`${b.kind}|${b.subject}`)),
    headline: headlineFor(suppressedJoin.kept.length, collided)
  };
}

function headlineFor(corroborations: number, collided: { contradictions: unknown[]; silences: unknown[]; undischarged: unknown[] }): string {
  const parts: string[] = [];
  if (corroborations > 0) parts.push(`${corroborations} topic(s) with more than one independent opinion`);
  if (collided.contradictions.length > 0) parts.push(`${collided.contradictions.length} contradiction(s) awaiting human review`);
  if (collided.silences.length > 0) parts.push(`${collided.silences.length} assumption(s) falsified by a determination`);
  if (collided.undischarged.length > 0) parts.push(`${collided.undischarged.length} assumption(s) nobody checked`);
  if (parts.length === 0) return "Nothing composed: no shared subject with a declared conflict space. This is not agreement — it is incomparability.";
  return `${parts.join("; ")}. No severity, score or tier is computed by this protocol.`;
}

/**
 * A composition result is signed as an in-toto statement, but it is **not a claim**: it has no predicate
 * in the registry and cannot enter a join. That is what stops composition results from corroborating
 * anything — not a rule about depth, but a type that cannot be an input.
 */
export function compositionStatement(result: CompositionResult): InTotoStatement<CompositionResult> {
  const digest = createHash("sha256").update([...result.inputs].sort().join("\n"), "utf8").digest("hex");
  return {
    _type: STATEMENT_TYPE,
    subject: [{ uri: `maru:composition/${digest}`, digest: { sha256: digest } }],
    predicateType: COMPOSITION_PREDICATE_TYPE,
    predicate: result
  };
}
