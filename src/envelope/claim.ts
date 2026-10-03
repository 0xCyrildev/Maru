import { MalformedClaimError, ProjectionMismatchError, UnknownEmitterError, UnknownRegistryError } from "../lib/errors.js";
import { buildSubjectUri, encodeValue, parseSubjectUri, type SubjectKind } from "../lib/encode.js";
import { claimIdFromProjection, lineageKeyFromFacet, projectClaim } from "../ids/claim.js";
import {
  REGISTRY_MAJOR,
  assertValue,
  lookupPredicate,
  mayAssert,
  type EmitterKind,
  type PredicateDef
} from "../registry/core.js";

export type Channel = "assert" | "assume";

/**
 * How the emitter came to know what it knows. Trust follows mechanism: a `deterministic` reading
 * outranks a `rules` table, which outranks a model. A `model` or `fallback` claim is reported and is
 * never a witness, because the channel that asserted it is the channel under test.
 *
 * Conversion is not a value here. A claim re-serialised from another format carries whatever provenance
 * its source stated, so "was this converted?" belongs to `methodology.emitter` ("imported"), which an
 * adapter must set and cannot inherit. Keying the witness rule on this enum instead was a hole: every
 * imported claim arrived as `deterministic` and qualified as a second opinion.
 */
export type Provenance = "deterministic" | "rules" | "model" | "fallback";

export type WitnessEligibility = "eligible" | "report-only";

/**
 * `full` — every identity field was reproducible from the emitter's own inputs.
 * `partial` — the claim names fields it could not pin. Partial claims are reported and are never
 * witnesses: a second opinion whose subject you cannot identify is not a second opinion.
 */
export type Verifiability = "full" | "partial";

export type UnverifiableReason = "truncated" | "conditional" | "opaque";

export type SeveritySignal = "informational" | "low" | "medium" | "high" | "critical";

/**
 * What an emitter did with a field it found, kept in three categories because the consequences differ:
 *  - `unverifiableFields` — identity-bearing and not pinnable, so the claim is `partial` and cannot witness.
 *  - `coercedFields` — whose raw type varied in the source data and was canonicalized by an encoder.
 *    Auditable rather than clean: recorded so a reader can see the coercion instead of re-deriving it.
 *  - `droppedFields` — carried nothing the predicate models (prose, or a field outside the projection).
 *    Recorded so a reader can see what was left out instead of inferring it was never there.
 */
export type DroppedReason = "prose" | "not-projected";

export interface UnverifiableField {
  field: string;
  reason: UnverifiableReason;
}

export interface DroppedField {
  field: string;
  reason: DroppedReason;
}

export interface Lineage {
  /** What the emitter says this claim is about, in one string. Facets are how "same construct" is declared. */
  facet: string;
  key: string;
  /**
   * `derived` — the data itself carries the identity (an object id, an address, a function).
   * `declared` — a human said these shapes are one construct. Both are honest; only `derived` may be
   * trusted to survive a new detector, so the distinction is kept rather than flattened.
   */
  basis: "derived" | "declared";
  note: string | null;
}

export interface Methodology {
  tool: string;
  toolVersion: string;
  check: string;
  checkVersion: string;
  emitter: EmitterKind;
}

export interface Target {
  kind: "transaction" | "package" | "object" | "none";
  network: string;
  digest: string | null;
}

export interface Limit {
  /** Stable id, so a limitation can be referenced across releases. Prose alone cannot be compared. */
  id: string;
  text: string;
}

export interface Claim {
  maru: "maru/claim/v1";
  claimId: string;
  registryMajor: number;
  channel: Channel;
  predicate: string;
  subjectUri: string;
  /** Encoded, in the registry's declared argument order. */
  args: Record<string, string>;
  value: string;
  lineage: Lineage;
  witness: WitnessEligibility;
  verifiability: Verifiability;
  /**
   * What the emitter itself asked for, before any downgrade. Without this, "the tool declined to vouch
   * for this claim" and "the protocol overruled the tool" are indistinguishable in the output — and only
   * the second is something the tool's author should argue with.
   */
  declaredByEmitter: WitnessEligibility;
  unverifiableFields: UnverifiableField[];
  coercedFields: string[];
  droppedFields: DroppedField[];
  provenance: Provenance;
  methodology: Methodology;
  target: Target;
  severitySignal: SeveritySignal;
  /** What the finding pointed at — for a signal claim, the violation's own message. Never hashed. */
  findingMessage: string | null;
  limits: Limit[];
  /** Everything the emitter observed that is not part of identity. Never hashed, never compared. */
  evidence: Record<string, string>;
  emittedAt: string;
}

export interface ClaimInput {
  channel: Channel;
  predicate: string;
  subjectKind: SubjectKind;
  /** Raw parts for the subject, encoded by kind. */
  subject: unknown[];
  /** Raw values keyed by the predicate's declared argument names. */
  args: Record<string, unknown>;
  value: unknown;
  facet: string;
  lineageBasis: "derived" | "declared";
  lineageNote?: string | null;
  witness: WitnessEligibility;
  provenance: Provenance;
  methodology: Methodology;
  target: Target;
  severitySignal: SeveritySignal;
  unverifiableFields?: UnverifiableField[];
  coercedFields?: string[];
  droppedFields?: DroppedField[];
  limits?: Limit[];
  findingMessage?: string;
  evidence?: Record<string, string>;
  emittedAt?: string;
  registryMajor?: number;
}

function sortFields<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => key(a).localeCompare(key(b)));
}

function encodeArgs(def: PredicateDef, raw: Record<string, unknown>, where: string): { ordered: string[]; encoded: Record<string, string> } {
  const declared = new Set(def.args.map((a) => a.name));
  for (const key of Object.keys(raw)) {
    if (!declared.has(key)) {
      throw new MalformedClaimError(
        `Predicate "${def.id}" does not declare argument "${key}" (declared: ${def.args.map((a) => a.name).join(", ") || "none"}). Extra arguments are refused, not dropped — dropping one silently changes identity.`
      );
    }
  }
  const encoded: Record<string, string> = {};
  const ordered: string[] = [];
  for (const arg of def.args) {
    if (!(arg.name in raw)) {
      throw new MalformedClaimError(`Predicate "${def.id}" requires argument "${arg.name}" (${where}).`);
    }
    const value = encodeValue(arg.encoder, raw[arg.name], `${where}.${arg.name}`);
    encoded[arg.name] = value;
    ordered.push(value);
  }
  return { ordered, encoded };
}

/**
 * The single place a claim is admitted. Everything is checked against the registry and nothing is
 * coerced: an unregistered predicate, an out-of-domain value, a missing or extra argument, a subject
 * in the wrong namespace, or an emitter kind the predicate does not permit all stop the build.
 */
export function buildClaim(input: ClaimInput): Claim {
  const major = input.registryMajor ?? REGISTRY_MAJOR;
  if (major !== REGISTRY_MAJOR) throw new UnknownRegistryError(major, REGISTRY_MAJOR);

  const def = lookupPredicate(input.predicate, major);
  const where = `${def.id}#${input.channel}`;

  if (!def.emitters.includes(input.methodology.emitter)) {
    throw new MalformedClaimError(
      `Predicate "${def.id}" may be asserted by ${def.emitters.join(" or ")} only; "${input.methodology.emitter}" cannot speak it, because the mechanism that produced the value is what makes it trustworthy.`
    );
  }
  if (!isKnownEmitterKind(input.methodology.emitter)) throw new UnknownEmitterError(input.methodology.emitter);

  const subjectUri = buildSubjectUri(input.subjectKind, input.subject);
  const parsed = parseSubjectUri(subjectUri);
  if (parsed.kind !== def.subjectKind) {
    throw new MalformedClaimError(
      `Predicate "${def.id}" is about "${def.subjectKind}", but the subject "${subjectUri}" is a "${parsed.kind}". A mismatch here would let two claims about different things collide.`
    );
  }

  const { ordered, encoded } = encodeArgs(def, input.args, where);
  const value = encodeValue(def.valueEncoder, input.value, `${where}.value`);
  assertValue(def, value);

  if (input.channel === "assume" && input.witness === "eligible") {
    throw new MalformedClaimError(
      `Claim "${def.id}" is an assumption and cannot be witness-eligible. An assumption is a precondition the emitter did not check; it cannot corroborate anything, least of all itself.`
    );
  }
  if (input.channel === "assert" && !mayAssert(def, input.methodology.emitter)) {
    const allowed = (def.assertEmitters ?? def.emitters).join(" or ");
    throw new MalformedClaimError(
      `An "${input.methodology.emitter}" emitter may only assume "${def.id}"; only ${allowed} may assert it. Asserting across that line is exactly the move that turns a guess into evidence.`
    );
  }

  const unverifiable = sortFields(input.unverifiableFields ?? [], (f) => `${f.field}|${f.reason}`);
  const verifiability: Verifiability = unverifiable.length === 0 ? "full" : "partial";
  // Anything excludeReason() will refuse must already be downgraded here, or a claim can arrive marked
  // witness:"eligible" and then be dropped from the join for a reason the envelope already knew.
  const neverWitnesses =
    verifiability === "partial" ||
    input.provenance === "model" ||
    input.provenance === "fallback" ||
    input.methodology.emitter === "imported";
  const witness: WitnessEligibility = input.witness === "eligible" && neverWitnesses ? "report-only" : input.witness;

  const projection = projectClaim({
    registryMajor: major,
    predicate: def.id,
    subjectUri,
    argsOrdered: ordered,
    value,
    channel: input.channel
  });

  return {
    maru: "maru/claim/v1",
    claimId: claimIdFromProjection(projection),
    registryMajor: major,
    channel: input.channel,
    predicate: def.id,
    subjectUri,
    args: encoded,
    value,
    lineage: {
      facet: input.facet,
      key: lineageKeyFromFacet(input.facet),
      basis: input.lineageBasis,
      note: input.lineageNote ?? null
    },
    witness,
    declaredByEmitter: input.witness,
    verifiability,
    unverifiableFields: unverifiable,
    coercedFields: sortFields(input.coercedFields ?? [], (f) => f),
    droppedFields: sortFields(input.droppedFields ?? [], (f) => `${f.field}|${f.reason}`),
    provenance: input.provenance,
    methodology: input.methodology,
    target: input.target,
    severitySignal: input.severitySignal,
    findingMessage: input.findingMessage ?? null,
    limits: [...(input.limits ?? [])].sort((a, b) => a.id.localeCompare(b.id)),
    evidence: Object.fromEntries(Object.entries(input.evidence ?? {}).sort(([a], [b]) => a.localeCompare(b))),
    emittedAt: input.emittedAt ?? "1970-01-01T00:00:00.000Z"
  };
}

const EMITTER_KINDS: EmitterKind[] = ["dynamic-trace", "static-source", "imported", "composition"];

function isKnownEmitterKind(kind: string): kind is EmitterKind {
  return EMITTER_KINDS.includes(kind as EmitterKind);
}

/** Recomputes identity from the claim's own fields. A mismatch means the bytes were edited after signing. */
export function assertClaimId(claim: Claim): void {
  const def = lookupPredicate(claim.predicate, claim.registryMajor);
  const ordered = def.args.map((a) => {
    const value = claim.args[a.name];
    if (value === undefined) throw new MalformedClaimError(`Claim is missing its recorded argument "${a.name}".`);
    return value;
  });
  const projection = projectClaim({
    registryMajor: claim.registryMajor,
    predicate: claim.predicate,
    subjectUri: claim.subjectUri,
    argsOrdered: ordered,
    value: claim.value,
    channel: claim.channel
  });
  const recomputed = claimIdFromProjection(projection);
  if (recomputed !== claim.claimId) {
    throw new ProjectionMismatchError(claim.claimId, recomputed);
  }
}
