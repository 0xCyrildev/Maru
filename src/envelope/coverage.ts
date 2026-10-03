/**
 * The orthogonal "this was not looked at" channel. Absence of a finding is not a negative claim, and
 * a run that did not happen is not a clean run, so completeness travels *beside* the claims and is
 * never expressed as a claim value. A registry domain that contained "unresolved" or "unrecorded"
 * would let a reader take "nobody looked" for evidence that something is fine.
 */
export type CoverageKind =
  | "skipped"
  | "not-read"
  | "ambiguous"
  | "detector-error"
  | "empty-run"
  | "range-incomplete";

export interface CoverageRecord {
  kind: CoverageKind;
  /** What was not covered: a digest, a checkpoint range, a detector name. */
  subject: string;
  reason: string;
  toolId: string;
}

export function coverageIsSilentRun(records: readonly CoverageRecord[]): boolean {
  return records.some((r) => r.kind === "empty-run");
}

/** One line that must appear verbatim when nothing was actually examined. */
export function coverageHeadline(records: readonly CoverageRecord[]): string | null {
  if (coverageIsSilentRun(records)) return "EMPTY RUN — no transaction was examined; this is not a clean result.";
  const errors = records.filter((r) => r.kind === "detector-error");
  if (errors.length === 0) return null;
  return `INCOMPLETE — ${errors.length} detector(s) failed while running; an absent finding here is an uncomputed finding.`;
}
