import { MaruError } from "../lib/errors.js";
import { isEnvelope, verifyEnvelope, type VerifiedClaim } from "../dsse/verify.js";
import type { DsseEnvelope } from "../dsse/sign.js";
import type { Keyring } from "../dsse/keyring.js";
import type { CoverageRecord } from "./coverage.js";

export interface ClaimsetDocument {
  maru: "maru/claimset/v1";
  envelopes: DsseEnvelope[];
  coverage: CoverageRecord[];
}

export function isClaimset(value: unknown): value is ClaimsetDocument {
  if (typeof value !== "object" || value === null) return false;
  const doc = value as Partial<ClaimsetDocument>;
  return doc.maru === "maru/claimset/v1" && Array.isArray(doc.envelopes);
}

export function makeClaimset(envelopes: DsseEnvelope[], coverage: CoverageRecord[]): ClaimsetDocument {
  return { maru: "maru/claimset/v1", envelopes, coverage: [...coverage] };
}

export interface LoadResult {
  envelopes: DsseEnvelope[];
  coverage: CoverageRecord[];
}

/** One document is either a claimset or a single envelope; both are accepted so a tool can hand over one claim. */
export function loadDocument(value: unknown, source: string): LoadResult {
  if (isClaimset(value)) return { envelopes: value.envelopes, coverage: value.coverage ?? [] };
  if (isEnvelope(value)) return { envelopes: [value], coverage: [] };
  throw new MaruError("MALFORMED_DOCUMENT", `${source} is neither a Maru claimset nor a DSSE envelope.`);
}

export function verifyAll(documents: { doc: unknown; source: string }[], ring: Keyring): { verified: VerifiedClaim[]; coverage: CoverageRecord[]; failures: { source: string; error: string }[] } {
  const verified: VerifiedClaim[] = [];
  const coverage: CoverageRecord[] = [];
  const failures: { source: string; error: string }[] = [];

  for (const { doc, source } of documents) {
    let loaded: LoadResult;
    try {
      loaded = loadDocument(doc, source);
    } catch (error) {
      failures.push({ source, error: error instanceof Error ? error.message : String(error) });
      continue;
    }
    coverage.push(...loaded.coverage);
    for (const envelope of loaded.envelopes) {
      try {
        verified.push(verifyEnvelope(envelope, ring));
      } catch (error) {
        failures.push({ source, error: error instanceof Error ? error.message : String(error) });
      }
    }
  }

  return { verified, coverage, failures };
}
