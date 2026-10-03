/**
 * Library entry point. A consumer that imports Maru programmatically must not pull in the CLI: the CLI
 * module reads process.argv on import, which would hijack any tool that imported the root index. This
 * file is the reason it exists, and it is not duplication.
 */
export { REGISTRY_MAJOR, PREDICATES, CONFLICT_GROUPS, lookupPredicate, registryVersion } from "./registry/core.js";
export type { PredicateDef, ConflictGroup, EmitterKind, ConflictMode } from "./registry/core.js";
export { buildClaim, assertClaimId } from "./envelope/claim.js";
export type { Claim, ClaimInput, Lineage, Limit, Methodology, Target, UnverifiableField, DroppedField } from "./envelope/claim.js";
export { toStatement, statementBytes, parseStatement, FINDING_PREDICATE_TYPE, COMPOSITION_PREDICATE_TYPE } from "./envelope/statement.js";
export { makeClaimset, loadDocument, verifyAll } from "./envelope/claimset.js";
export { coverageHeadline } from "./envelope/coverage.js";
export type { CoverageRecord, CoverageKind } from "./envelope/coverage.js";
export { signStatement, DSSE_PAYLOAD_TYPE } from "./dsse/sign.js";
export type { DsseEnvelope } from "./dsse/sign.js";
export { verifyEnvelope } from "./dsse/verify.js";
export type { VerifiedClaim } from "./dsse/verify.js";
export { loadKeyring, parseKeyring, saveKeyring, withEntry, withoutKey } from "./dsse/keyring.js";
export type { Keyring, KeyringEntry } from "./dsse/keyring.js";
export { generateKey, keyIdForJwk, privateKeyFromSeed, publicKeyOf } from "./dsse/keys.js";
export type { Ed25519Jwk } from "./dsse/keys.js";
export { compose, compositionStatement, ENGINE } from "./ops/compose.js";
export type { CompositionResult, SuppressedCorroboration } from "./ops/compose.js";
export { join, topicOf } from "./ops/join.js";
export type { Corroboration, Overlap, Opinion, TopicGroup, JoinResult } from "./ops/join.js";
export { collide } from "./ops/collision.js";
export type { Contradiction, Silence, Discharged, Undischarged } from "./ops/collision.js";
export { partition, exclusionReason } from "./ops/refuse.js";
export { renderClaims, renderComposition, renderCoverage } from "./ops/render.js";
export { chaseToClaims } from "./adapters/chase/index.js";
export { parseAnalysisReport, parseTrace } from "./adapters/chase/wire.js";
export { driftCheck, EMISSIONS, LIMITS, REPORT_ONLY_TYPES } from "./adapters/chase/methodology.js";
export { claimsFromSource, parseMoveDirectory } from "./emitters/move-static/index.js";
export { exportSarif, importSarif } from "./adapters/sarif/index.js";
export { MaruError } from "./lib/errors.js";
export { encodeValue, buildSubjectUri } from "./lib/encode.js";
export { claimIdFromProjection, lineageKeyFromFacet, projectClaim } from "./ids/claim.js";
