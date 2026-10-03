import { buildClaim, type Claim } from "../../envelope/claim.js";
import type { CoverageRecord } from "../../envelope/coverage.js";
import { ADAPTER_CHECK, CHASE_TOOL } from "./methodology.js";
import { FACET } from "./facets.js";
import type { ChaseOwnerKind, ChaseTrace } from "./wire.js";

export interface TraceFacts {
  claims: Claim[];
  coverage: CoverageRecord[];
}

const OWNER_VALUE: Partial<Record<ChaseOwnerKind, string>> = {
  address: "address",
  "consensus-address": "consensus-address",
  object: "object",
  shared: "shared",
  immutable: "immutable"
};

const CHANGE_VALUE = new Set(["created", "mutated", "deleted"]);

function methodology() {
  return {
    tool: CHASE_TOOL.id,
    toolVersion: CHASE_TOOL.version,
    check: ADAPTER_CHECK.id,
    checkVersion: ADAPTER_CHECK.version,
    emitter: "dynamic-trace" as const
  };
}

/**
 * Facts a trace determines on its own, before any detector runs. This is the layer Maru composes:
 * it is what a static tool can agree with, disagree with, or falsify an assumption against.
 *
 * Two things are deliberately *not* turned into claims. `unresolved` (the owner was looked at and
 * could not be classified) and `unrecorded` (the trace was normalised before owners were captured)
 * become coverage records, because a value in an ownership domain would read as a determination that
 * nobody made. And where one object is reported two different ways, the adapter says `multiple` or
 * records the ambiguity instead of picking the row that makes the report quiet.
 */
export function factsFromTrace(trace: ChaseTrace, network: string, emittedAt: string): TraceFacts {
  const claims: Claim[] = [];
  const coverage: CoverageRecord[] = [];
  const digest = trace.digest;
  const target = { kind: "transaction" as const, network, digest };

  const changeByObject = new Map<string, Set<string>>();
  const ownerByObject = new Map<string, Set<string>>();
  const ownerAmbiguity = new Map<string, string>();

  for (const row of trace.objectChanges) {
    if (!row.objectId) continue;
    if (row.changeType && CHANGE_VALUE.has(row.changeType)) {
      const set = changeByObject.get(row.objectId) ?? new Set<string>();
      set.add(row.changeType);
      changeByObject.set(row.objectId, set);
    }
    const kind = row.outputOwnerKind;
    if (kind === undefined) {
      ownerAmbiguity.set(row.objectId, "unrecorded");
      continue;
    }
    if (kind === "unrecorded") {
      ownerAmbiguity.set(row.objectId, "unrecorded");
      continue;
    }
    if (kind === "unresolved") {
      ownerAmbiguity.set(row.objectId, "unresolved");
      continue;
    }
    const value = OWNER_VALUE[kind];
    if (!value) {
      ownerAmbiguity.set(row.objectId, `unknown-owner-kind:${kind}`);
      continue;
    }
    const set = ownerByObject.get(row.objectId) ?? new Set<string>();
    set.add(value);
    ownerByObject.set(row.objectId, set);
  }

  for (const [objectId, values] of [...changeByObject.entries()].sort()) {
    const value = values.size > 1 ? "multiple" : [...values][0];
    if (!value) continue;
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.object.change",
        subjectKind: "sui:object",
        subject: [objectId],
        args: { network, digest },
        value,
        facet: FACET.objectChanges(objectId),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target,
        severitySignal: "informational",
        emittedAt,
        evidence: { changeTypesSeen: [...values].sort().join(","), objectId }
      })
    );
  }

  for (const [objectId, values] of [...ownerByObject.entries()].sort()) {
    if (values.size > 1) {
      coverage.push({
        kind: "ambiguous",
        subject: objectId,
        reason: `The trace reported ${[...values].sort().join(" and ")} as the output owner of the same object; no ownership fact was derived.`,
        toolId: CHASE_TOOL.id
      });
      continue;
    }
    const value = [...values][0];
    if (!value) continue;
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.object.ownership",
        subjectKind: "sui:object",
        subject: [objectId],
        args: { network },
        value,
        facet: FACET.objectChanges(objectId),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target: { kind: "object", network, digest },
        severitySignal: "informational",
        emittedAt,
        evidence: { objectId }
      })
    );
  }

  for (const [objectId, reason] of [...ownerAmbiguity.entries()].sort()) {
    coverage.push({
      kind: reason === "unrecorded" ? "not-read" : "ambiguous",
      subject: objectId,
      reason:
        reason === "unrecorded"
          ? "This trace was normalised before output owners were captured, so nobody looked. Absence of an ownership claim here is not evidence about ownership."
          : reason === "unresolved"
            ? "The owner was looked at and could not be classified — in practice a change with no output owner, which is what a deleted object looks like."
            : `Output owner was reported as "${reason}", which core@1 does not model.`,
      toolId: CHASE_TOOL.id
    });
  }

  const netByCoin = new Map<string, { owner: string; coinType: string; total: bigint; rows: number; coerced: boolean }>();
  for (const row of trace.balanceChanges) {
    if (!row.owner || !row.coinType) continue;
    let amount: bigint;
    let coerced = false;
    if (typeof row.amount === "number") {
      if (!Number.isSafeInteger(row.amount)) {
        coverage.push({ kind: "ambiguous", subject: `${row.owner}|${row.coinType}`, reason: "Balance change arrived as a float beyond safe integer range; no delta claim was derived.", toolId: CHASE_TOOL.id });
        continue;
      }
      amount = BigInt(row.amount);
      coerced = true;
    } else {
      if (!/^-?(0|[1-9][0-9]*)$/.test(row.amount)) {
        coverage.push({ kind: "ambiguous", subject: `${row.owner}|${row.coinType}`, reason: `Balance change "${row.amount}" is not a canonical decimal; no delta claim was derived.`, toolId: CHASE_TOOL.id });
        continue;
      }
      amount = BigInt(row.amount);
    }
    const key = `${row.owner}|${row.coinType}`;
    const entry = netByCoin.get(key) ?? { owner: row.owner, coinType: row.coinType, total: 0n, rows: 0, coerced: false };
    entry.total += amount;
    entry.rows += 1;
    entry.coerced = entry.coerced || coerced;
    netByCoin.set(key, entry);
  }

  for (const [key, entry] of [...netByCoin.entries()].sort()) {
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.balance.delta",
        subjectKind: "sui:address-coin",
        subject: [entry.owner, entry.coinType],
        args: { network, digest },
        value: entry.total.toString(),
        facet: FACET.balanceChanges(entry.owner, entry.coinType),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target,
        severitySignal: "informational",
        emittedAt,
        coercedFields: entry.coerced ? ["amount"] : [],
        evidence: { rows: String(entry.rows), summed: key }
      })
    );
  }

  const indicesByModule = new Map<string, { packageId: string; module: string; indices: number[] }>();
  const refByFunction = new Map<string, { packageId: string; module: string; function: string; values: Set<boolean> }>();
  const unresolvedSignatures: string[] = [];

  for (const command of trace.ptbCommands) {
    if (command.kind !== "MoveCall" || !command.packageId || !command.module) continue;
    const moduleKey = `${command.packageId}::${command.module}`;
    const bucket = indicesByModule.get(moduleKey) ?? { packageId: command.packageId, module: command.module, indices: [] };
    if (Number.isInteger(command.index)) bucket.indices.push(command.index);
    indicesByModule.set(moduleKey, bucket);

    if (!command.function) continue;
    if (command.returnsMutableRef === undefined) {
      unresolvedSignatures.push(`${moduleKey}::${command.function}`);
      continue;
    }
    const fnKey = `${moduleKey}::${command.function}`;
    const fn = refByFunction.get(fnKey) ?? { packageId: command.packageId, module: command.module, function: command.function, values: new Set<boolean>() };
    fn.values.add(command.returnsMutableRef);
    refByFunction.set(fnKey, fn);
  }

  for (const [moduleKey, bucket] of [...indicesByModule.entries()].sort()) {
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.ptb.calls",
        subjectKind: "sui:package-module",
        subject: [bucket.packageId, bucket.module],
        args: { network, digest },
        value: bucket.indices,
        facet: FACET.commandIndex(bucket.packageId, bucket.module),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target,
        severitySignal: "informational",
        emittedAt,
        evidence: { module: moduleKey, callCount: String(bucket.indices.length) }
      })
    );
  }

  for (const [fnKey, fn] of [...refByFunction.entries()].sort()) {
    if (fn.values.size > 1) {
      coverage.push({
        kind: "ambiguous",
        subject: fnKey,
        reason: "The resolved signature reported both a mutable and an immutable return for the same function in one transaction; no reference-return fact was derived.",
        toolId: CHASE_TOOL.id
      });
      continue;
    }
    const mutable = [...fn.values][0] === true;
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.ref.return.observed",
        subjectKind: "sui:function",
        subject: [fn.packageId, fn.module, fn.function],
        args: { network, digest },
        value: mutable ? "mutable" : "immutable",
        facet: FACET.resolvedSignature(fn.packageId, fn.module, fn.function),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target,
        severitySignal: "informational",
        emittedAt,
        evidence: { function: fnKey }
      })
    );
  }

  for (const fnKey of [...new Set(unresolvedSignatures)].sort()) {
    coverage.push({
      kind: "not-read",
      subject: fnKey,
      reason: "The MoveCall signature could not be resolved, so whether it returned a mutable reference is unknown — not immutable.",
      toolId: CHASE_TOOL.id
    });
  }

  const emittingPackages = new Set(trace.events.map((e) => `${e.packageId}::${e.module}`));
  for (const [moduleKey, bucket] of [...indicesByModule.entries()].sort()) {
    const present = emittingPackages.has(moduleKey);
    claims.push(
      buildClaim({
        channel: "assert",
        predicate: "move.event.presence",
        subjectKind: "sui:package-module",
        subject: [bucket.packageId, bucket.module],
        args: { network, digest },
        value: present ? "present" : "absent",
        facet: FACET.events(bucket.packageId, bucket.module),
        lineageBasis: "derived",
        witness: "eligible",
        provenance: "deterministic",
        methodology: methodology(),
        target,
        severitySignal: "informational",
        emittedAt,
        evidence: {
          module: moduleKey,
          basis: present ? "an event from this module appears in the trace" : "the event array was read in full and contained no event from this module"
        }
      })
    );
  }

  return { claims, coverage };
}
