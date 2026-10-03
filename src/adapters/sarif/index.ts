import { MalformedClaimError } from "../../lib/errors.js";
import type { Claim } from "../../envelope/claim.js";
import type { CoverageRecord } from "../../envelope/coverage.js";
import { assertClaimId } from "../../envelope/claim.js";
import { FINDING_PREDICATE_TYPE, parseStatement, toStatement, type InTotoStatement } from "../../envelope/statement.js";
import { lookupPredicate } from "../../registry/core.js";
import { parseSubjectUri } from "../../lib/encode.js";

/**
 * SARIF 2.1.0 interchange. This exists to prove Maru composes *over* the plumbing that already exists
 * rather than competing with it, and its limit is stated in the same breath as its capability:
 *
 * `export` projects claims into a SARIF log any scanner consumer can read.
 * `import` round-trips claims that were themselves exported (they travel in `originalProperties.maru`),
 * and **refuses** a foreign SARIF result rather than inventing a subject for it. core@1 has namespaces
 * for Sui objects, functions, modules, coins and transactions — none for file-and-region. A SARIF result
 * about `src/Vault.sol:42` is therefore convertible and *not* composable, and pretending otherwise would
 * be exactly the fabricated agreement this protocol is here to prevent.
 */
export interface SarifLocation {
  physicalLocation?: { artifactLocation?: { uri?: string }; region?: unknown };
  logicalLocations?: { logicalName?: string; fullyQualifiedName?: string }[];
}

export interface SarifResult {
  ruleId: string;
  level?: "none" | "note" | "warning" | "error";
  message: { text: string };
  locations?: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  suppressions?: { kind: string }[];
  originalProperties?: Record<string, unknown>;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: {
    tool: { driver: { name: string; version?: string; rules?: { id: string; shortDescription?: { text: string } }[] } };
    results: SarifResult[];
  }[];
}

export const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

const SEVERITY_TO_LEVEL: Record<Claim["severitySignal"], "none" | "note" | "warning" | "error"> = {
  informational: "note",
  low: "note",
  medium: "warning",
  high: "error",
  critical: "error"
};

export function exportSarif(claims: readonly Claim[], coverage: readonly CoverageRecord[]): SarifLog {
  const byTool = new Map<string, Claim[]>();
  for (const claim of claims) {
    const key = `${claim.methodology.tool}@${claim.methodology.toolVersion}`;
    const bucket = byTool.get(key) ?? [];
    bucket.push(claim);
    byTool.set(key, bucket);
  }

  const runs = [...byTool.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([toolKey, list]) => {
    const [name, version] = toolKey.split("@");
    return {
      tool: {
        driver: {
          name: name ?? toolKey,
          ...(version ? { version } : {}),
          rules: [...new Set(list.map((c) => c.predicate))].sort().map((id) => ({ id, shortDescription: { text: lookupPredicate(id).meaning } }))
        }
      },
      results: list
        .slice()
        .sort((a, b) => a.claimId.localeCompare(b.claimId))
        .map((claim) => toSarifResult(claim, coverage))
    };
  });

  return { $schema: SARIF_SCHEMA, version: "2.1.0", runs };
}

function toSarifResult(claim: Claim, coverage: readonly CoverageRecord[]): SarifResult {
  const statement = toStatement(claim);
  return {
    ruleId: claim.predicate,
    level: SEVERITY_TO_LEVEL[claim.severitySignal],
    message: { text: claim.findingMessage ?? `${claim.predicate} = ${claim.value} about ${claim.subjectUri}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: claim.subjectUri } } }],
    // partialFingerprints is SARIF's nearest analogue to a claim identity, and it is a heuristic over
    // artifact text. Maru's claimId is stronger and is carried alongside it, not substituted by it.
    partialFingerprints: { maruClaimId: claim.claimId },
    ...(claim.witness === "report-only" ? { suppressions: [{ kind: "external" }] } : {}),
    originalProperties: {
      maru: statement,
      lineage: claim.lineage,
      verifiability: claim.verifiability,
      unverifiableFields: claim.unverifiableFields,
      droppedFields: claim.droppedFields,
      coercedFields: claim.coercedFields,
      limits: claim.limits,
      provenance: claim.provenance,
      coverageNotice: coverage.length > 0 ? `${coverage.length} coverage record(s) accompany this claim` : undefined
    }
  };
}

export interface SarifImport {
  claims: Claim[];
  refused: { ruleId: string; reason: string }[];
}

export function importSarif(log: unknown): SarifImport {
  if (typeof log !== "object" || log === null) throw new MalformedClaimError("SARIF log must be an object.");
  const candidate = log as Partial<SarifLog>;
  if (candidate.version !== "2.1.0" || !Array.isArray(candidate.runs)) {
    throw new MalformedClaimError(`Unsupported SARIF document (version ${String(candidate.version)}); Maru speaks 2.1.0.`);
  }

  const claims: Claim[] = [];
  const refused: { ruleId: string; reason: string }[] = [];

  for (const run of candidate.runs) {
    for (const result of run.results ?? []) {
      const embedded = result.originalProperties?.maru;
      if (isStatementValue(embedded)) {
        const claim = parseStatement(embedded).predicate;
        assertClaimId(claim);
        claims.push(claim);
        continue;
      }
      refused.push({
        ruleId: result.ruleId ?? "(no ruleId)",
        reason: "This SARIF result carries no Maru claim and core@1 declares no subject namespace for a file-and-region finding. It can be converted for display, not composed: inventing a subject to make it participate would fabricate agreement."
      });
    }
  }

  return { claims: claims.sort((a, b) => a.claimId.localeCompare(b.claimId)), refused: refused.sort((a, b) => a.ruleId.localeCompare(b.ruleId)) };
}

function isStatementValue(value: unknown): value is InTotoStatement<Claim> {
  if (typeof value !== "object" || value === null) return false;
  const s = value as Partial<InTotoStatement<unknown>>;
  return s._type === "https://in-toto.io/Statement/v1" && s.predicateType === FINDING_PREDICATE_TYPE;
}

/** Re-exported so the gate can assert no claim reaches SARIF with an unparseable subject URI. */
export function subjectKindOfUri(uri: string): string {
  return parseSubjectUri(uri).kind;
}
