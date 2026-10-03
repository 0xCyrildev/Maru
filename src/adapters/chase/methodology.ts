import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { Limit } from "../../envelope/claim.js";
import type { ChaseSeverity } from "./wire.js";

export const CHASE_TOOL = { id: "chase", name: "@zeroxcyril/chase", version: "0.3.0" } as const;
export const ADAPTER_CHECK = { id: "chase-adapter", version: "0.0.1" } as const;

export interface Emission {
  checker: string;
  severity: ChaseSeverity;
  /**
   * Chase's own `corroborates: false`, recovered from the detector declarations. It is *not* on the
   * wire: a `Violation` carries no corroboration marker, so it only exists in the table.
   */
  corroborates: boolean;
  /** Name-matched rather than structurally determined. A name match is a weaker claim and says so. */
  nameBased: boolean;
}

export const EMISSIONS: Readonly<Record<string, Emission>> = Object.freeze({
  ADDRESS_OUTFLOW: { checker: "address-balance-delta", severity: "low", corroborates: true, nameBased: false },
  COIN_NET_IMBALANCE: { checker: "coin-net-imbalance", severity: "low", corroborates: true, nameBased: false },
  MUTABLE_REFERENCE_RETURNED: { checker: "mutable-access", severity: "high", corroborates: true, nameBased: false },
  UNEXPECTED_TRANSFER: { checker: "ownership-anomaly", severity: "medium", corroborates: true, nameBased: false },
  CAPABILITY_TRANSFER: { checker: "capability-transfer", severity: "high", corroborates: true, nameBased: false },
  ORACLE_MANIPULATION_SUSPECTED: { checker: "oracle-pattern", severity: "high", corroborates: true, nameBased: true },
  REPEATED_MODULE_CALLS: { checker: "repeated-module-calls", severity: "low", corroborates: true, nameBased: false },
  REENTRANCY_PATTERN: { checker: "reentrancy-pattern", severity: "medium", corroborates: true, nameBased: false },
  FLASH_LOAN_SHAPED: { checker: "flash-loan-shaped", severity: "medium", corroborates: true, nameBased: true },
  DYNAMIC_FIELD_CREATED: { checker: "dynamic-field-lifecycle", severity: "low", corroborates: false, nameBased: false },
  DYNAMIC_FIELD_DELETED: { checker: "dynamic-field-lifecycle", severity: "low", corroborates: false, nameBased: false },
  UNANNOUNCED_OBJECT_CHANGE: { checker: "silent-object-change", severity: "low", corroborates: false, nameBased: false }
});

export const REPORT_ONLY_TYPES: ReadonlySet<string> = new Set(
  Object.entries(EMISSIONS)
    .filter(([, e]) => !e.corroborates)
    .map(([type]) => type)
);

/**
 * Stable limit ids. Chase records its limitations as unversioned English, report-level, covering four
 * of twelve types; a limit with an id can be compared across releases and referenced by another tool.
 * Every type carries at least one limit, including the ones whose premise core@1 cannot express —
 * saying "this premise is not in the registry" is a result, not an omission.
 */
export const LIMITS: Readonly<Record<string, Limit[]>> = Object.freeze({
  ADDRESS_OUTFLOW: [
    { id: "limit.address-balance-delta.shared-object-inflow", text: "Fires on shared-object inflows; the recipient side does not appear in the gRPC balanceChanges array." },
    { id: "limit.address-balance-delta.address-scoped", text: "Scoped to an address, not to an object, so a shared-object swap can move value this claim cannot see." }
  ],
  COIN_NET_IMBALANCE: [
    { id: "limit.coin-net-imbalance.summed-view", text: "Sums the whole balanceChange array instead of reading it per address, so it restates a scoping artifact rather than a new fact." }
  ],
  MUTABLE_REFERENCE_RETURNED: [
    { id: "limit.mutable-access.signature-only", text: "Determines that a mutable reference crossed a package boundary; does not verify that the caller uses it unsafely." },
    { id: "limit.mutable-access.indirect-paths", text: "Does not follow indirect access paths through dynamic fields or wrapped objects." },
    { id: "limit.core.premise-expressible", text: "Rests on a Move-source premise (who controls the value) which core@1 records as an assumption and cannot determine from a trace." }
  ],
  UNEXPECTED_TRANSFER: [
    { id: "limit.ownership-anomaly.recipient-kind", text: "Classifies the recipient from the recorded output owner; a deleted object has no output owner and is `unresolved`, which is not a value." }
  ],
  CAPABILITY_TRANSFER: [
    { id: "limit.capability-transfer.treasury-legitimate", text: "TreasuryCap transfers legitimately surface here; the claim reports a shape, not a misuse." }
  ],
  ORACLE_MANIPULATION_SUSPECTED: [
    { id: "limit.oracle-pattern.name-based", text: "Name-matched. Legitimate protocols that update their own oracle and then act on it trip it." }
  ],
  REPEATED_MODULE_CALLS: [
    { id: "limit.repeated-module-calls.threshold-5", text: "Threshold is tuned to 5; genuine patterns below 5 go unreported." }
  ],
  REENTRANCY_PATTERN: [
    { id: "limit.core.premise-not-expressible", text: "Premise is a call-ordering pattern with no object identity in the evidence; core@1 declares no predicate for it, so it enters no topic and cannot corroborate." }
  ],
  FLASH_LOAN_SHAPED: [
    { id: "limit.flash-loan-shaped.name-based", text: "Name-matched on borrow/action/repay keywords." },
    { id: "limit.core.premise-not-expressible", text: "Premise is that the borrow and the repay are causally linked; no predicate in core@1 expresses causal linkage, so this claim cannot compose." }
  ],
  DYNAMIC_FIELD_CREATED: [{ id: "limit.dynamic-field-lifecycle.ordinary", text: "A field appearing is ordinary traffic; reported, never a witness." }],
  DYNAMIC_FIELD_DELETED: [{ id: "limit.dynamic-field-lifecycle.ordinary", text: "A field vanishing is ordinary traffic; reported, never a witness." }],
  UNANNOUNCED_OBJECT_CHANGE: [
    { id: "limit.silent-object-change.silence-is-ordinary", text: "A large share of mainnet transactions emit nothing at all; silence here is ordinary and is not a finding." }
  ]
});

export function limitsFor(type: string): Limit[] {
  return LIMITS[type] ?? [];
}

export interface DriftReport {
  checked: boolean;
  reason: string | null;
  differences: string[];
}

/**
 * The adapter keeps a local copy of Chase's detector table, so the copy can rot. This reads the table
 * back out of Chase's own source when it is present on the machine and reports every difference.
 * When Chase is absent the answer is `checked: false` — never a silent pass.
 */
export function driftCheck(chaseSourceDir: string): DriftReport {
  const invariantsDir = join(chaseSourceDir, "src", "invariants");
  if (!existsSync(invariantsDir)) {
    return { checked: false, reason: `No Chase source tree at ${invariantsDir}; the local detector table was not verified.`, differences: [] };
  }
  const differences: string[] = [];
  const seen = new Set<string>();
  for (const file of readdirSync(invariantsDir).filter((f) => f.endsWith(".ts") && f !== "index.ts")) {
    const source = readFileSync(join(invariantsDir, file), "utf8");
    const checker = /name:\s*"([^"]+)"/.exec(source)?.[1];
    const emitsBlock = [...source.matchAll(/emits:\s*\[([\s\S]*?)\],/g)].map((m) => m[1]).join(" ");
    const types = [...emitsBlock.matchAll(/type:\s*"([^"]+)"/g)].map((m) => m[1]).filter((x): x is string => Boolean(x));
    const severities = [...emitsBlock.matchAll(/severity:\s*"([^"]+)"/g)].map((m) => m[1]).filter((x): x is string => Boolean(x));
    const corroboratesFalse = /corroborates:\s*false/.test(emitsBlock);

    types.forEach((type, i) => {
      seen.add(type);
      const local = EMISSIONS[type];
      if (!local) {
        differences.push(`${type}: Chase emits it and the adapter has no entry.`);
        return;
      }
      if (checker && local.checker !== checker) differences.push(`${type}: checker is "${checker}" in Chase, "${local.checker}" here.`);
      const severity = severities[i];
      if (severity && local.severity !== severity) differences.push(`${type}: severity is ${severity} in Chase, ${local.severity} here.`);
      if (local.corroborates === corroboratesFalse) {
        differences.push(`${type}: corroborates is ${String(!corroboratesFalse)} here, Chase declares ${String(!corroboratesFalse ? false : true)}.`);
      }
    });
  }
  for (const type of Object.keys(EMISSIONS)) {
    if (!seen.has(type)) differences.push(`${type}: the adapter knows it and no Chase checker emits it any more.`);
  }
  return { checked: true, reason: null, differences };
}
