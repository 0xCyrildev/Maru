import { MalformedClaimError } from "../lib/errors.js";
import type { Claim } from "./claim.js";

export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const FINDING_PREDICATE_TYPE = "https://maru.dev/predicate/finding/v1";
export const COMPOSITION_PREDICATE_TYPE = "https://maru.dev/predicate/composition/v1";

export interface ResourceDescriptor {
  uri: string;
  digest: Record<string, string>;
}

export interface InTotoStatement<P = Claim> {
  _type: typeof STATEMENT_TYPE;
  subject: ResourceDescriptor[];
  predicateType: string;
  predicate: P;
}

/**
 * Maru is an in-toto Statement carrying a Maru predicate, in a DSSE envelope. Nothing here is
 * invented: the predicateType URI is the only new identifier, and it is an identifier — it is not a
 * resolvable site, and the spec says so rather than implying a registry nobody built.
 *
 * Why the subject is the claim's own projection: an in-toto subject digest must be a content digest,
 * and Maru refuses to synthesize one for a transaction it did not hash. The on-chain target therefore
 * travels in `predicate.target`, where it can be checked, rather than in a digest that would read as
 * provenance it does not have.
 */
export function toStatement(claim: Claim): InTotoStatement<Claim> {
  return {
    _type: STATEMENT_TYPE,
    subject: [{ uri: `maru:claim/${claim.claimId}`, digest: { sha256: claim.claimId } }],
    predicateType: FINDING_PREDICATE_TYPE,
    predicate: claim
  };
}

export function statementBytes(statement: InTotoStatement<unknown>): Buffer {
  return Buffer.from(JSON.stringify(statement), "utf8");
}

export function isStatement(value: unknown): value is InTotoStatement<Claim> {
  if (typeof value !== "object" || value === null) return false;
  const s = value as Partial<InTotoStatement<unknown>>;
  return s._type === STATEMENT_TYPE && Array.isArray(s.subject) && typeof s.predicateType === "string";
}

export function parseStatement(value: unknown): InTotoStatement<Claim> {
  if (!isStatement(value)) throw new MalformedClaimError("Not an in-toto Statement v1 document (`_type`/`subject`/`predicateType` missing).");
  if (value.subject.length === 0) throw new MalformedClaimError("Statement has an empty subject list; in-toto requires at least one.");
  if (value.predicateType !== FINDING_PREDICATE_TYPE) {
    throw new MalformedClaimError(`Unexpected predicateType "${value.predicateType}" — expected a Maru finding or composition predicate.`);
  }
  const claim = value.predicate as Partial<Claim> | undefined;
  if (!claim || typeof claim.claimId !== "string") {
    throw new MalformedClaimError("Statement carries no Maru claim predicate (`predicate.claimId` missing).");
  }
  return value as InTotoStatement<Claim>;
}
