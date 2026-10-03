import { MalformedClaimError, SignatureError, ToolKeyMismatchError } from "../lib/errors.js";
import { assertClaimId, type Claim } from "../envelope/claim.js";
import { parseStatement, type InTotoStatement } from "../envelope/statement.js";
import { findKey, type Keyring } from "./keyring.js";
import { pae } from "./pae.js";
import { verifyBytes } from "./keys.js";
import type { DsseEnvelope } from "./sign.js";

export interface VerifiedClaim {
  claim: Claim;
  statement: InTotoStatement<Claim>;
  /** Whose key signed this. This is the only thing that makes a claim attributable. */
  signer: { keyId: string; toolId: string; note: string };
  payloadBytes: number;
}

export function isEnvelope(value: unknown): value is DsseEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const e = value as Partial<DsseEnvelope>;
  return typeof e.payloadType === "string" && typeof e.payload === "string" && Array.isArray(e.signatures);
}

/**
 * Verification is three separate checks, and all three have to pass:
 *  1. the signature is valid over the exact payload bytes,
 *  2. the key that made it is pinned in the ring (an unattributed signature is not trusted, it is unknown),
 *  3. the claim's own identity recomputes from its fields — so nobody can sign a claim and then edit
 *     the predicate, subject or value inside it.
 * A signature proves *who said it*, never *whether it is true*.
 */
export function verifyEnvelope(envelope: DsseEnvelope, ring: Keyring): VerifiedClaim {
  if (!isEnvelope(envelope)) throw new MalformedClaimError("Not a DSSE envelope (payloadType/payload/signatures missing).");
  if (envelope.signatures.length === 0) throw new MalformedClaimError("Envelope carries no signatures; there is nobody to attribute it to.");

  const payload = Buffer.from(envelope.payload, "base64");
  const auth = pae(envelope.payloadType, payload);
  let statement: InTotoStatement<Claim>;
  try {
    statement = parseStatement(JSON.parse(payload.toString("utf8")));
  } catch (error) {
    // A damaged payload is a Maru refusal, not a SyntaxError escaping to the caller: a consumer that
    // catches one error type must never have to guess whether the other means "invalid" or "my bug".
    throw new MalformedClaimError(`Payload is not a parseable Maru statement: ${error instanceof Error ? error.message : String(error)}`);
  }

  let matched: VerifiedClaim | null = null;
  const failures: string[] = [];

  for (const signature of envelope.signatures) {
    const entry = findKey(ring, signature.keyid);
    const ok = verifyBytes(entry.jwk, auth, Buffer.from(signature.sig, "base64"));
    if (!ok) {
      failures.push(signature.keyid);
      continue;
    }
    assertClaimId(statement.predicate);
    if (statement.predicate.methodology.tool !== entry.toolId) {
      throw new ToolKeyMismatchError(statement.predicate.methodology.tool, entry.toolId, entry.keyId);
    }
    matched = {
      claim: statement.predicate,
      statement,
      signer: { keyId: entry.keyId, toolId: entry.toolId, note: entry.note },
      payloadBytes: payload.length
    };
    break;
  }

  if (!matched) {
    throw new SignatureError(failures.join(", ") || "none");
  }
  return matched;
}

/** Every signature must belong to a pinned key, even once one has verified — a stray signature is a finding about the document. */
export function allSigners(envelope: DsseEnvelope, ring: Keyring): string[] {
  return envelope.signatures.map((s) => findKey(ring, s.keyid).toolId).sort();
}
