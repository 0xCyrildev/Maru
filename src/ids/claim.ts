import { createHash } from "node:crypto";

export const CLAIM_DOMAIN = "maru/claim/v1";
export const LINEAGE_DOMAIN = "maru/lineage/v1";

/** Record separator: cannot appear in any encoder output, so a projection is never ambiguous. */
const SEP = "\x1e";

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/**
 * The projection is the only thing Maru hashes for identity: a fixed tuple in a declared argument
 * order, every element already passed through its registry encoder.
 *
 * Evidence is deliberately NOT hashed. Most of it cannot be pinned across releases — arrays are
 * truncation-sampled, prose lives inside structured fields, keys appear only for some data shapes —
 * and a claim identity that depends on unreproducible bytes would silently renumber findings whenever
 * an emitter tidied its evidence. What cannot be pinned is named in `unverifiableFields` instead.
 *
 * Tool identity is also excluded on purpose: two tools saying the same thing produce the same
 * claimId, which is what makes agreement detectable. The producer lives in `methodology` and in the
 * envelope keyid. Severity is excluded so a re-rating does not create a new claim.
 */
export function projectClaim(parts: {
  registryMajor: number;
  predicate: string;
  subjectUri: string;
  argsOrdered: string[];
  value: string;
  channel: string;
}): string {
  // The argument count is part of the tuple so a predicate with no arguments cannot project to the
  // same bytes as one whose sole argument is empty.
  const args = `${parts.argsOrdered.length}:${parts.argsOrdered.join(SEP)}`;
  return [
    CLAIM_DOMAIN,
    String(parts.registryMajor),
    parts.predicate,
    parts.subjectUri,
    args,
    parts.value,
    parts.channel
  ].join(SEP);
}

export function claimIdFromProjection(projection: string): string {
  return sha256(projection);
}

/**
 * Lineage answers "is this the same construct, or a second opinion about it?" Two claims corroborate
 * only when their lineage keys differ. The facet is supplied by the emitter — derived where the data
 * actually carries identity, declared where it does not — and never inferred from a name.
 */
export function lineageKeyFromFacet(facet: string): string {
  if (facet.includes(SEP)) throw new Error(`Lineage facet must not contain the record separator: "${facet}"`);
  return sha256(`${LINEAGE_DOMAIN}${SEP}${facet}`);
}
