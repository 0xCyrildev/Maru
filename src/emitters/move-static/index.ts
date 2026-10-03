import { buildClaim, type Claim, type Limit } from "../../envelope/claim.js";
import { buildSubjectUri } from "../../lib/encode.js";
import { STATIC_TOOL } from "./tool.js";
import { isImmutableReference, isPrimitive, isMutableReference, isTxContext, parseMoveDirectory, type MoveFunction } from "./source.js";

export interface StaticInput {
  sourceDir: string;
  network: string;
  /** Named address in the source to a published package id. Unmapped modules are skipped, never guessed. */
  packageAddresses: Record<string, string>;
  emittedAt: string;
  /**
   * The transaction this source was read *for*. Event presence is a runtime fact, so a source reader may
   * only assume it; the digest is the question it is answering, not something the source knows.
   */
  digest?: string | undefined;
}

export interface StaticOutput {
  claims: Claim[];
  notes: string[];
}

const LIMITS: Limit[] = [
  { id: "limit.move-static.regex-not-compiler", text: "Source is parsed by regular expressions, not by the Move compiler: imports, aliases, constants and script-visible types are invisible to it." },
  { id: "limit.move-static.no-control-flow", text: "Classifies what a signature and body text make visible. It does not determine whether a declared return value is ever produced, so it says nothing about unreachability." },
  { id: "limit.move-static.single-file-modules", text: "Assumes one `module` header per file; a file with nested module blocks yields one module." }
];

function methodology(check: string) {
  return {
    tool: STATIC_TOOL.id,
    toolVersion: STATIC_TOOL.version,
    check,
    checkVersion: STATIC_TOOL.version,
    emitter: "static-source" as const
  };
}

function canonicalSignature(fn: MoveFunction): string {
  const generics = fn.typeParameters.length > 0 ? `<${fn.typeParameters.join(",")}>` : "";
  const params = fn.params.map((p) => p.type.replace(/\s+/g, " ")).join(",");
  return `${fn.module}::${fn.name}${generics}(${params})->${fn.returns?.replace(/\s+/g, " ") ?? "unit"}`;
}

/**
 * Who supplies the mutable handles this function receives.
 *
 * This is a signature question and a source reader can determine it: `caller` when the function takes a
 * mutable reference (or an owned struct) that is not the transaction context, `internal` when it takes
 * none and still reaches mutable state through `object::get_mut` / `dynamic_field` borrowing. Anything
 * else is undecidable here and emits nothing — an empty answer is recorded as a note rather than
 * quietly becoming `internal`, which is exactly the collapse this protocol exists to prevent.
 */
function valueControl(fn: MoveFunction): "caller" | "internal" | null {
  const meaningful = fn.params.filter((p) => !isTxContext(p.type));
  const receivesHandle = meaningful.some((p) => isMutableReference(p.type) || (!isPrimitive(p.type) && !isImmutableReference(p.type)));
  const reachesInside = /\bobject::get_mut\b|\bdynamic_field::borrow(?:_mut)?\b|\bborrow_mut\b/.test(fn.body);
  if (receivesHandle) return "caller";
  if (reachesInside) return "internal";
  return null;
}

/**
 * Emitter #2. It reads Move *source*, which makes it a different mechanism from a transaction trace,
 * and it deliberately shares subject space with one: a published package id resolved from the source's
 * named address is the same `sui:function` a trace names. That is what lets two tools corroborate,
 * contradict, or falsify each other's premises instead of merely both describing the same file.
 */
export function claimsFromSource(input: StaticInput): StaticOutput {
  const modules = parseMoveDirectory(input.sourceDir);
  const claims: Claim[] = [];
  const notes: string[] = [];

  for (const module of modules) {
    const packageId = input.packageAddresses[module.addressName];
    if (!packageId) {
      notes.push(`module ${module.addressName}::${module.name}: no published package id for address name "${module.addressName}"; nothing emitted. Refusing to guess an id, because a guessed subject is worse than a missing one.`);
      continue;
    }

    for (const fn of module.functions) {
      const subject = [packageId, module.name, fn.name];
      const subjectUri = buildSubjectUri("sui:function", [packageId, module.name, fn.name]);
      const target = { kind: "package" as const, network: input.network, digest: null };

      claims.push(
        buildClaim({
          channel: "assert",
          predicate: "move.function.signature",
          subjectKind: "sui:function",
          subject,
          args: { package: packageId },
          value: canonicalSignature(fn),
          facet: `source:signature|${subjectUri}`,
          lineageBasis: "derived",
          witness: "eligible",
          provenance: "deterministic",
          methodology: methodology("declared-signature"),
          target,
          severitySignal: "informational",
          limits: LIMITS,
          evidence: { file: fn.file, visibility: fn.visibility },
          emittedAt: input.emittedAt
        })
      );

      const returnsMutable = fn.returns !== null && isMutableReference(fn.returns);
      claims.push(
        buildClaim({
          channel: "assert",
          predicate: "move.ref.return.declared",
          subjectKind: "sui:function",
          subject,
          args: { package: packageId },
          value: returnsMutable ? "mutable" : "immutable",
          facet: `source:declared-return|${subjectUri}`,
          lineageBasis: "derived",
          witness: "eligible",
          provenance: "deterministic",
          methodology: methodology("declared-return"),
          target,
          severitySignal: "informational",
          limits: LIMITS,
          evidence: { declaredReturn: fn.returns ?? "unit" },
          emittedAt: input.emittedAt
        })
      );

      const control = valueControl(fn);
      if (control === null) {
        notes.push(`${module.name}::${fn.name}: takes no mutable handle and reaches no internal borrow in the visible body, so handle supply is undetermined here. No claim emitted — an unrecorded premise is not a discharged one.`);
        continue;
      }
      claims.push(
        buildClaim({
          channel: "assert",
          predicate: "move.value.control",
          subjectKind: "sui:function",
          subject,
          args: { package: packageId },
          value: control,
          facet: `source:parameter-list|${subjectUri}`,
          lineageBasis: "derived",
          witness: "eligible",
          provenance: "deterministic",
          methodology: methodology("handle-supply"),
          target,
          severitySignal: "informational",
          limits: LIMITS,
          evidence: { params: fn.params.map((p) => `${p.name}:${p.type}`).join(",") },
          emittedAt: input.emittedAt
        })
      );
    }
    if (input.digest) {
      const moduleUri = buildSubjectUri("sui:package-module", [packageId, module.name]);
      claims.push(
        buildClaim({
          channel: "assume",
          predicate: "move.event.presence",
          subjectKind: "sui:package-module",
          subject: [packageId, module.name],
          args: { network: input.network, digest: input.digest },
          value: module.emitsEvent ? "present" : "absent",
          facet: `source:event-emit-text|${moduleUri}`,
          lineageBasis: "declared",
          lineageNote:
            "Read from the presence of `event::emit` text in the module. That does not establish the statement is on a path this transaction reached, which is why this is an assumption and not an assertion.",
          witness: "report-only",
          provenance: "rules",
          methodology: methodology("declared-event-presence"),
          target: { kind: "transaction", network: input.network, digest: input.digest },
          severitySignal: "informational",
          limits: LIMITS,
          evidence: { emitsEventText: String(module.emitsEvent), digestIsQuestionContext: "true" },
          emittedAt: input.emittedAt
        })
      );
    }
  }

  return { claims, notes };
}

export { parseMoveDirectory } from "./source.js";
