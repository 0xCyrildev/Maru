import { buildClaim, type Claim, type DroppedField, type UnverifiableField } from "../../envelope/claim.js";
import { buildSubjectUri } from "../../lib/encode.js";
import type { CoverageRecord } from "../../envelope/coverage.js";
import { ADAPTER_CHECK, CHASE_TOOL, EMISSIONS, REPORT_ONLY_TYPES, limitsFor } from "./methodology.js";
import { FACET, premisesFor } from "./facets.js";
import type { ChaseAnalysisReport, ChaseViolation } from "./wire.js";

/**
 * Chase's evidence bag is `Record<string, unknown>` with no schema, so every field name it is known to
 * carry is classified here. The three categories decide what Maru is allowed to conclude:
 *  - `projected`  — a scalar, carried into the claim's evidence.
 *  - `prose`      — a human sentence, dropped from structure but recorded.
 *  - the rest     — identity-bearing and not pinnable (embedded command objects, truncation-sampled
 *    arrays, keys that only exist for some data shapes), recorded as unverifiable.
 * A field that is not in this table is reported as unclassified rather than silently ignored: an
 * ignored field is how a protocol starts claiming it saw everything.
 */
const FIELD_CLASS: Readonly<Record<string, "projected" | "prose" | "opaque" | "truncated" | "conditional">> = Object.freeze({
  note: "prose",
  message: "prose",
  classification: "prose",
  reason: "prose",
  oracleCmd: "opaque",
  defiCmd: "opaque",
  borrow: "opaque",
  action: "opaque",
  repay: "opaque",
  nonFrameworkCalls: "truncated",
  eventPackages: "truncated",
  debitedAddresses: "truncated",
  creditedAddresses: "truncated",
  perAddress: "truncated",
  eventsInTrace: "truncated",
  otherNonFrameworkPackages: "truncated",
  parentObject: "conditional",
  recipientObject: "conditional",
  address: "projected",
  coinType: "projected",
  net: "projected",
  direction: "projected",
  perAddressTruncated: "projected",
  nonFrameworkCallCount: "projected",
  suiExcluded: "projected",
  balanceChangeRowCount: "projected",
  caller: "projected",
  package: "projected",
  module: "projected",
  function: "projected",
  commandIndex: "projected",
  calleePackage: "projected",
  crossesPackageBoundaryInThisPtb: "projected",
  objectId: "projected",
  objectType: "projected",
  changeType: "projected",
  recipient: "projected",
  recipientKind: "projected",
  previousOwner: "projected",
  sender: "projected",
  oracleIndex: "projected",
  defiIndex: "projected",
  count: "projected",
  firstIndex: "projected",
  secondIndex: "projected",
  priorOccurrenceIndex: "projected",
  interveningIndex: "projected",
  intervenedBy: "projected",
  fieldType: "projected",
  keyType: "projected",
  valueType: "projected",
  valuePackageSpoke: "projected",
  changedPackage: "projected",
  eventsInTx: "projected",
  eventPackageCount: "projected"
});

export interface ReportClaims {
  claims: Claim[];
  coverage: CoverageRecord[];
  unclassified: string[];
}

function classifyEvidence(violation: ChaseViolation, unclassified: Set<string>): {
  evidence: Record<string, string>;
  unverifiable: UnverifiableField[];
  dropped: DroppedField[];
} {
  const evidence: Record<string, string> = {};
  const unverifiable: UnverifiableField[] = [];
  const dropped: DroppedField[] = [];

  for (const [field, value] of Object.entries(violation.evidence ?? {})) {
    const klass = FIELD_CLASS[field];
    if (klass === undefined) {
      unclassified.add(`${violation.type}.${field}`);
      dropped.push({ field, reason: "not-projected" });
      continue;
    }
    if (klass === "projected") {
      evidence[field] = typeof value === "string" ? value : JSON.stringify(value);
      continue;
    }
    if (klass === "prose") {
      dropped.push({ field, reason: "prose" });
      continue;
    }
    unverifiable.push({ field, reason: klass });
  }

  return { evidence, unverifiable, dropped };
}

/**
 * What a detector firing *is*: a signal claim. It carries the severity and the limits and nothing
 * else, and the registry puts it outside the algebra — so two detectors labelling the same
 * transaction differently is never reported as a contradiction about the transaction, and a second
 * label never raises anything's priority.
 *
 * Alongside each signal, the premises the finding rests on are emitted as explicit `assume` claims
 * where core@1 can express them, which is what lets another tool discharge or silence them.
 */
export function claimsFromReport(report: ChaseAnalysisReport, emittedAt: string): ReportClaims {
  const claims: Claim[] = [];
  const coverage: CoverageRecord[] = [];
  const unclassified = new Set<string>();
  const network = report.network;
  const target = { kind: "transaction" as const, network, digest: report.digest };

  for (const violation of report.violations) {
    const emission = EMISSIONS[violation.type];
    if (!emission) {
      coverage.push({
        kind: "ambiguous",
        subject: violation.type,
        reason: "Chase emitted a violation type the adapter has no entry for. It is reported as an unknown, not folded into a similar one.",
        toolId: CHASE_TOOL.id
      });
      continue;
    }
    const { evidence, unverifiable, dropped } = classifyEvidence(violation, unclassified);

    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.finding.signal",
        subjectKind: "sui:transaction",
        subject: [report.digest],
        args: { network },
        value: violation.type,
        facet: `detector:${emission.checker}|${report.digest}`,
        lineageBasis: "derived",
        witness: "report-only",
        provenance: emission.nameBased ? "rules" : "deterministic",
        methodology: {
          tool: CHASE_TOOL.id,
          toolVersion: CHASE_TOOL.version,
          check: emission.checker,
          checkVersion: CHASE_TOOL.version,
          emitter: "dynamic-trace"
        },
        target,
        severitySignal: violation.severity,
        unverifiableFields: unverifiable,
        droppedFields: dropped,
        limits: limitsFor(violation.type),
        evidence,
        findingMessage: violation.message,
        emittedAt
      })
    );

    if (violation.severity !== emission.severity) {
      coverage.push({
        kind: "ambiguous",
        subject: violation.type,
        reason: `The violation arrived at ${violation.severity} while the detector declares ${emission.severity}. Both are recorded; neither is reconciled.`,
        toolId: CHASE_TOOL.id
      });
    }

    for (const premise of premisesFor(violation)) {
      const subject = premise.subjectFrom(violation);
      if (!subject) {
        coverage.push({
          kind: "not-read",
          subject: violation.type,
          reason: `Premise "${premise.name}" needs a function subject the evidence did not carry, so it was not recorded as an assumption — an unrecorded premise is not a discharged one.`,
          toolId: CHASE_TOOL.id
        });
        continue;
      }
      claims.push(
        buildClaim({
          channel: "assume",
          predicate: premise.predicate,
          subjectKind: "sui:function",
          subject: [subject.packageId, subject.module, subject.function],
          args: { package: subject.packageId },
          value: premise.value,
          facet: FACET.assumption(
            premise.name,
            buildSubjectUri("sui:function", [subject.packageId, subject.module, subject.function])
          ),
          lineageBasis: "declared",
          lineageNote: premise.note,
          witness: "report-only",
          provenance: "rules",
          methodology: {
            tool: CHASE_TOOL.id,
            toolVersion: CHASE_TOOL.version,
            check: ADAPTER_CHECK.id,
            checkVersion: ADAPTER_CHECK.version,
            emitter: "dynamic-trace"
          },
          target,
          severitySignal: "informational",
          limits: [{ id: `premise:${premise.name}`, text: premise.note }],
          evidence: { derivedFromSignal: violation.type, note: premise.note },
          emittedAt
        })
      );
    }
  }

  for (const error of report.detectorErrors) {
    coverage.push({ kind: "detector-error", subject: error, reason: "A detector threw while running; a finding that did not appear here was never computed.", toolId: CHASE_TOOL.id });
  }

  const lifecycle = new Map<string, { objectId: string; keyType: string; created: boolean; deleted: boolean; eligible: boolean }>();
  for (const violation of report.violations) {
    if (violation.type !== "DYNAMIC_FIELD_CREATED" && violation.type !== "DYNAMIC_FIELD_DELETED") continue;
    const evidence = violation.evidence ?? {};
    const objectId = typeof evidence.objectId === "string" ? evidence.objectId : null;
    const keyType = typeof evidence.keyType === "string" ? evidence.keyType : null;
    if (!objectId || !keyType) {
      coverage.push({
        kind: "not-read",
        subject: violation.type,
        reason: "The dynamic-field evidence carried no parent object or no key type, so no lifecycle fact could be derived from it.",
        toolId: CHASE_TOOL.id
      });
      continue;
    }
    const entry = lifecycle.get(`${objectId}|${keyType}`) ?? { objectId, keyType, created: false, deleted: false, eligible: true };
    if (violation.type === "DYNAMIC_FIELD_CREATED") entry.created = true;
    else entry.deleted = true;
    if (REPORT_ONLY_TYPES.has(violation.type)) entry.eligible = false;
    lifecycle.set(`${objectId}|${keyType}`, entry);
  }

  for (const [key, entry] of [...lifecycle.entries()].sort()) {
    const value = entry.created && entry.deleted ? "cycle" : entry.created ? "created" : "deleted";
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.dynamicField.lifecycle",
        subjectKind: "sui:object",
        subject: [entry.objectId],
        args: { network, digest: report.digest, keyType: entry.keyType },
        value,
        facet: FACET.dynamicFields(entry.objectId, entry.keyType),
        lineageBasis: "derived",
        witness: entry.eligible ? "eligible" : "report-only",
        provenance: "deterministic",
        methodology: {
          tool: CHASE_TOOL.id,
          toolVersion: CHASE_TOOL.version,
          check: "dynamic-field-lifecycle",
          checkVersion: CHASE_TOOL.version,
          emitter: "dynamic-trace"
        },
        target,
        severitySignal: "informational",
        emittedAt,
        evidence: { summedFrom: key, created: String(entry.created), deleted: String(entry.deleted) }
      })
    );
  }

  if (report.violations.length === 0 && report.stats.ptbCommands === 0) {
    coverage.push({ kind: "empty-run", subject: report.digest, reason: "Nothing was examined: this is an empty run, not a clean result.", toolId: CHASE_TOOL.id });
  }

  return { claims, coverage, unclassified: [...unclassified].sort() };
}

export function reportOnlyTypes(): string[] {
  return [...REPORT_ONLY_TYPES].sort();
}
