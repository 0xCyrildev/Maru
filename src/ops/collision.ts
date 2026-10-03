import type { Claim } from "../envelope/claim.js";
import { lookupPredicate, sharedConflictSpace, spaceValuesConflict, type ConflictSpace } from "../registry/core.js";

export interface ClaimRef {
  claimId: string;
  predicate: string;
  channel: "assert" | "assume";
  value: string;
  tool: string;
  emitter: string;
  provenance: string;
}

export interface Contradiction {
  relation: "contradict";
  subjectUri: string;
  space: string;
  values: [string, string];
  left: ClaimRef;
  right: ClaimRef;
  /** Always. The protocol's job is to detect a contradiction, never to guess which tool is right. */
  nextAction: "human-review";
  note: string;
}

export interface Silence {
  relation: "silent";
  subjectUri: string;
  space: string;
  /** The claim whose premise is falsified. The finding is not deleted; its assumption is marked unsound. */
  assumption: ClaimRef;
  assertion: ClaimRef;
  note: string;
}

export interface Discharged {
  relation: "discharged";
  subjectUri: string;
  space: string;
  assumption: ClaimRef;
  assertion: ClaimRef;
}

export interface Undischarged {
  assumption: ClaimRef;
  subjectUri: string;
  reason: "nothing asserts about this subject" | "assertions exist, but in no conflict space shared with this assumption";
}

export function refOf(claim: Claim): ClaimRef {
  return {
    claimId: claim.claimId,
    predicate: claim.predicate,
    channel: claim.channel,
    value: claim.value,
    tool: claim.methodology.tool,
    emitter: claim.methodology.emitter,
    provenance: claim.provenance
  };
}

function spaceOf(a: Claim, b: Claim): ConflictSpace | null {
  const defA = lookupPredicate(a.predicate, a.registryMajor);
  const defB = lookupPredicate(b.predicate, b.registryMajor);
  return sharedConflictSpace(defA, defB);
}

/**
 * The one procedure behind `contradict`, `silent`, `discharged` and `undischarged`. Two claims are
 * comparable only when they share a subject *and* the registry declares a space they both speak in;
 * then either their values conflict, agree, or the pair is incomparable.
 *
 * The asymmetry is the point: `contradict` needs two assertions, `silent` needs exactly one. An
 * assertion cannot silence another assertion by itself — that is a dispute, and it goes to a human.
 */
export function collide(claims: readonly Claim[]): {
  contradictions: Contradiction[];
  silences: Silence[];
  discharged: Discharged[];
  undischarged: Undischarged[];
} {
  const contradictions: Contradiction[] = [];
  const silences: Silence[] = [];
  const discharged: Discharged[] = [];
  const dischargedIds = new Set<string>();
  const assertedSubjects = new Map<string, number>();

  for (const claim of claims) {
    if (claim.channel === "assert") {
      assertedSubjects.set(claim.subjectUri, (assertedSubjects.get(claim.subjectUri) ?? 0) + 1);
    }
  }

  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const a = claims[i] as Claim;
      const b = claims[j] as Claim;
      if (a.subjectUri !== b.subjectUri) continue;
      if (a.channel === "assert" && b.channel === "assert") continue;
      if (a.channel === "assume" && b.channel === "assume") continue;

      const space = spaceOf(a, b);
      if (!space) continue;

      const conflicting = spaceValuesConflict(space.domain, a.value, b.value);
      const assumption = a.channel === "assume" ? a : b;
      const assertion = a.channel === "assert" ? a : b;

      if (conflicting) {
        silences.push({
          relation: "silent",
          subjectUri: a.subjectUri,
          space: space.space,
          assumption: refOf(assumption),
          assertion: refOf(assertion),
          note: `The ${assumption.methodology.emitter} reading assumed "${assumption.value}" about ${a.subjectUri}; the ${assertion.methodology.emitter} reading determined "${assertion.value}". The finding rests on a premise another tool falsified.`
        });
      } else {
        discharged.push({
          relation: "discharged",
          subjectUri: a.subjectUri,
          space: space.space,
          assumption: refOf(assumption),
          assertion: refOf(assertion)
        });
        dischargedIds.add(assumption.claimId);
      }
    }
  }

  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const a = claims[i] as Claim;
      const b = claims[j] as Claim;
      if (a.channel !== "assert" || b.channel !== "assert") continue;
      if (a.subjectUri !== b.subjectUri) continue;
      const space = spaceOf(a, b);
      if (!space) continue;
      if (!spaceValuesConflict(space.domain, a.value, b.value)) continue;

      // The pair is oriented by claimId, not by input order. Two claims whose values cannot both hold
      // are one dispute; leaving left/right to whichever arrived first means the same disagreement
      // reports twice with the tools swapped, which breaks reproducibility across runs.
      const [first, second] = a.claimId.localeCompare(b.claimId) <= 0 ? [a, b] : [b, a];
      contradictions.push({
        relation: "contradict",
        subjectUri: first.subjectUri,
        space: space.space,
        values: [first.value, second.value],
        left: refOf(first),
        right: refOf(second),
        nextAction: "human-review",
        note: `Two assertions cannot both hold in space "${space.space}". Nothing here is resolved automatically: an unresolved disagreement reported as agreement is the failure this protocol exists to prevent.`
      });
    }
  }

  const undischarged: Undischarged[] = [];
  for (const claim of claims) {
    if (claim.channel !== "assume") continue;
    if (dischargedIds.has(claim.claimId)) continue;
    const touched = silences.some((s) => s.assumption.claimId === claim.claimId);
    if (touched) continue;
    const hasAssertionOnSubject = (assertedSubjects.get(claim.subjectUri) ?? 0) > 0;
    undischarged.push({
      assumption: refOf(claim),
      subjectUri: claim.subjectUri,
      reason: hasAssertionOnSubject
        ? "assertions exist, but in no conflict space shared with this assumption"
        : "nothing asserts about this subject"
    });
  }

  // Total orders, not partial ones: input order must not change a byte of the output, or the same
  // set of claims composes differently on two runs and a report stops being reproducible.
  const bySubjectThenClaims = <T extends { subjectUri: string }>(x: T, y: T, keys: (v: T) => string[]) => {
    const subject = x.subjectUri.localeCompare(y.subjectUri);
    if (subject !== 0) return subject;
    const a = keys(x).join("|");
    const b = keys(y).join("|");
    return a.localeCompare(b);
  };

  return {
    contradictions: contradictions.sort((x, y) =>
      bySubjectThenClaims(x, y, (v) => [v.space, v.left.claimId, v.right.claimId])
    ),
    silences: silences.sort((x, y) => bySubjectThenClaims(x, y, (v) => [v.space, v.assumption.claimId, v.assertion.claimId])),
    discharged: discharged.sort((x, y) => bySubjectThenClaims(x, y, (v) => [v.space, v.assumption.claimId, v.assertion.claimId])),
    undischarged: undischarged.sort((x, y) => bySubjectThenClaims(x, y, (v) => [v.assumption.claimId]))
  };
}
