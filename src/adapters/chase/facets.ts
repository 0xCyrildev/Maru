import type { ChaseViolation } from "./wire.js";

/**
 * Lineage answers "is this the same construct or a second opinion?", and here it is keyed on the
 * trace field a claim was read from — not on the detector that read it. Two detectors that both
 * looked at `objectChanges` are one opinion, which is the rule Chase already enforces by collapsing
 * corroboration to one representative per distinct type.
 *
 * The consequence is worth stating: Chase's `EXPECTED_OVERLAP` table (eleven type pairs, measured on
 * 308 mainnet transactions) has nothing to suppress in Maru, because the pair-wise overlaps live on
 * signal claims, and signals are outside the algebra by registry rule. The table is loaded, checked
 * for drift, and asserted *not* to be needed — see conformance/gates.ts.
 */
export const FACET = {
  objectChanges: (objectId: string) => `trace:object-changes|${objectId}`,
  balanceChanges: (address: string, coinType: string) => `trace:balance-changes|${address}|${coinType}`,
  commandIndex: (packageId: string, module: string) => `trace:command-index|${packageId}::${module}`,
  resolvedSignature: (packageId: string, module: string, fn: string) => `trace:resolved-signature|${packageId}::${module}::${fn}`,
  events: (packageId: string, module: string) => `trace:events|${packageId}::${module}`,
  dynamicFields: (objectId: string, keyType: string) => `violation:dynamic-field-lifecycle|${objectId}|${keyType}`,
  assumption: (name: string, subjectUri: string) => `declared-assumption:${name}|${subjectUri}`
} as const;

/**
 * Premises a finding rests on that another tool may be able to determine. Declared by the adapter,
 * never inferred: this is the adapter's claim about what the detector assumed, and the methodology
 * owner is entitled to disagree with it — which is why it carries a note and an id rather than hiding
 * inside a message string.
 */
export interface Premise {
  name: string;
  predicate: string;
  value: string;
  /** Which evidence field makes the subject, so a premise with no subject in the data is skipped rather than guessed. */
  subjectFrom: (violation: ChaseViolation) => { packageId: string; module: string; function: string } | null;
  note: string;
}

export const PREMISES: Readonly<Record<string, Premise[]>> = Object.freeze({
  MUTABLE_REFERENCE_RETURNED: [
    {
      name: "value-controlled-internally",
      predicate: "move.value.control",
      value: "internal",
      subjectFrom: (v) => {
        const e = v.evidence ?? {};
        const packageId = typeof e.package === "string" ? e.package : null;
        const module = typeof e.module === "string" ? e.module : null;
        const fn = typeof e.function === "string" ? e.function : null;
        return packageId && module && fn ? { packageId, module, function: fn } : null;
      },
      note: "The finding treats a mutable reference crossing a package boundary as a leak of state the transaction does not already hold. If the mutated value arrives from the caller's parameter list, that premise is false and the finding loses its force — and that is a Move-source question a trace cannot answer."
    }
  ]
});

export function premisesFor(violation: ChaseViolation): Premise[] {
  return PREMISES[violation.type] ?? [];
}
