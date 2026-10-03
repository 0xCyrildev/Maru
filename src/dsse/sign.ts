import type crypto from "node:crypto";
import { pae } from "./pae.js";
import { signBytes } from "./keys.js";
import { statementBytes, type InTotoStatement } from "../envelope/statement.js";

export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";

export interface DsseSignature {
  keyid: string;
  sig: string;
}

export interface DsseEnvelope {
  payloadType: typeof DSSE_PAYLOAD_TYPE;
  /** base64 of the statement bytes, signed exactly as they appear here. */
  payload: string;
  signatures: DsseSignature[];
}

export const ENVELOPE_MEDIA_TYPE = "application/vnd.in-toto+json+dss";

/**
 * Sign a statement over PAE(payloadType, payload) with Ed25519 — DSSE, not a Maru invention.
 * The payload is the serialized statement, kept as the same bytes that were hashed, so verification
 * never depends on re-serializing JSON and hoping the result matches.
 */
export function signStatement(
  statement: InTotoStatement<unknown>,
  signer: { keyId: string; privateKey: crypto.KeyObject }
): DsseEnvelope {
  const payload = statementBytes(statement);
  const auth = pae(DSSE_PAYLOAD_TYPE, payload);
  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload: payload.toString("base64"),
    signatures: [{ keyid: signer.keyId, sig: signBytes(signer.privateKey, auth).toString("base64") }]
  };
}
