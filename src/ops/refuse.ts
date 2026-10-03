import type { Claim, Provenance } from "../envelope/claim.js";

export type ExclusionReason =
  | "assumption (not an assertion)"
  | "witness-declared report-only by the emitter"
  | "partial verifiability — subject not pinnable"
  | "provenance model or fallback — the asserted channel is the channel under test"
  | "emitter imported — conversion is not a second opinion"
  | "composition result — never a witness";

export interface ExcludedClaim {
  claimId: string;
  predicate: string;
  reason: ExclusionReason;
  /**
   * What the emitter itself asked for, kept separate from the verdict. buildClaim() downgrades a claim
   * the emitter marked "eligible" whenever it cannot witness, so without this a reader could not tell
   * "the tool declined to vouch for itself" from "the protocol overruled the tool" — and only the second
   * one is worth arguing with.
   */
  declaredWitness: "eligible" | "report-only";
}

/**
 * A witness is a second *opinion*, not a second row. Everything here is a downgrade, never an upgrade:
 * a claim that cannot be excluded for a stated reason cannot corroborate anything.
 *
 * Order matters more than it looks. buildClaim() pre-empts `witness` to "report-only" for partial, model
 * and fallback claims, so testing `witness` first would report every one of them as "the emitter declared
 * it report-only" — which is false, and destroys the only field that answers "why was this left out?".
 * The specific cause is always named before the generic one.
 */
export function exclusionReason(claim: Claim): ExclusionReason | null {
  if (claim.channel === "assume") return "assumption (not an assertion)";
  if (claim.verifiability === "partial") return "partial verifiability — subject not pinnable";
  if (claim.provenance === "model" || claim.provenance === "fallback") {
    return "provenance model or fallback — the asserted channel is the channel under test";
  }
  if (claim.methodology.emitter === "imported") return "emitter imported — conversion is not a second opinion";
  if (claim.witness === "report-only") return "witness-declared report-only by the emitter";
  return null;
}


export function partition(claims: readonly Claim[]): { witnesses: Claim[]; excluded: ExcludedClaim[] } {
  const witnesses: Claim[] = [];
  const excluded: ExcludedClaim[] = [];
  for (const claim of claims) {
    const reason = exclusionReason(claim);
    if (reason === null) witnesses.push(claim);
    else excluded.push({ claimId: claim.claimId, predicate: claim.predicate, reason, declaredWitness: claim.declaredByEmitter });
  }
  return { witnesses, excluded };
}

export function provenancesOf(claims: readonly Claim[]): Provenance[] {
  return [...new Set(claims.map((c) => c.provenance))].sort() as Provenance[];
}
