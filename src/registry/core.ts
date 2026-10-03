import { MalformedClaimError, UnknownPredicateError, UnknownRegistryError, UnknownValueError } from "../lib/errors.js";
import type { EncoderName, SubjectKind } from "../lib/encode.js";

export const REGISTRY_NAME = "core" as const;
export const REGISTRY_MAJOR = 1;

/** What kind of producer made a claim. Trust follows mechanism, not name. */
export type EmitterKind = "dynamic-trace" | "static-source" | "imported" | "composition";

/**
 * `exclusive` — a closed domain where any two different values cannot both hold.
 * `distinct` — an open domain (a signature string, a signed delta) where any difference is a dispute.
 * core@1 declares no `pairwise` predicates: nothing in it needs a complement relation narrower than
 * "different", and a mode with no user is a mode nobody tests.
 */
export type ConflictMode = "exclusive" | "distinct";

export interface PredicateArg {
  name: string;
  encoder: EncoderName;
}

export interface PredicateDef {
  id: string;
  subjectKind: SubjectKind;
  args: PredicateArg[];
  /** null means an open domain; only legal with mode "distinct". */
  values: readonly string[] | null;
  mode: ConflictMode;
  /** How the value is canonicalized before it enters the projection. */
  valueEncoder: EncoderName;
  /** Cross-predicate collisions are only possible inside a declared group. */
  group: string | null;
  emitters: readonly EmitterKind[];
  /**
   * Which of `emitters` may *assert* rather than only assume. Absent means all of them may.
   * This is the axis that gives `silent` its direction: a source reader may assume what only a trace
   * can determine, so a static guess can be falsified by a measured fact but can never falsify one.
   */
  assertEmitters?: readonly EmitterKind[];
  /**
   * false means the predicate is reported but never enters the algebra — no topic, no collision, no
   * witness. Signal-shaped claims ("a detector fired") are not facts about the world, and letting two
   * of them share a subject-space would turn "different labels" into a contradiction.
   * Absent means true.
   */
  collidable?: boolean;
  meaning: string;
}

export function isCollidable(def: PredicateDef): boolean {
  return def.collidable ?? true;
}

export function mayAssert(def: PredicateDef, kind: EmitterKind): boolean {
  const allowed = def.assertEmitters ?? def.emitters;
  return allowed.includes(kind);
}

/**
 * core@1 — deliberately small, and its absences are visible. A proposition that is not here cannot
 * be assumed or determined, so it cannot enter the algebra: the registry's silence is not agreement,
 * and v0 reaches only the violation types that carry object, address, function or module identity.
 */
export const PREDICATES: readonly PredicateDef[] = [
  {
    id: "move.object.ownership",
    subjectKind: "sui:object",
    args: [{ name: "network", encoder: "network" }],
    values: ["address", "consensus-address", "object", "shared", "immutable"],
    mode: "exclusive",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace"],
    meaning:
      "Who owns the object after the transaction, as far as the trace can say. `unresolved` and `unrecorded` are NOT values here: they are coverage statements, and putting them in this domain would read 'nobody looked' as 'the owner is unknown'.",
  },
  {
    id: "move.object.change",
    subjectKind: "sui:object",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" }
    ],
    values: ["created", "mutated", "deleted", "absent", "multiple"],
    mode: "exclusive",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace"],
    meaning: "What this transaction did to one object. `multiple` is what an emitter says when it saw two different change types for the same object and refuses to pick one — collapsing the disagreement into a single token would hide a real inconsistency in the input."
  },
  {
    id: "move.dynamicField.lifecycle",
    subjectKind: "sui:object",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" },
      { name: "keyType", encoder: "typestring" }
    ],
    values: ["created", "deleted", "cycle", "absent"],
    mode: "exclusive",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace"],
    meaning: "A dynamic field of a given key type appearing on or vanishing from a parent object. `cycle` exists because teardown-and-replace is one construct: reporting created and deleted as two assertions about the same field would manufacture a contradiction out of an ordinary PTB."
  },
  {
    id: "move.event.presence",
    subjectKind: "sui:package-module",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" }
    ],
    values: ["present", "absent"],
    mode: "exclusive",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace", "static-source"],
    assertEmitters: ["dynamic-trace"],
    meaning: "Whether this package and module announced itself by event in this transaction. A trace determines it; a source reader may only assume it, which is what makes a static expectation falsifiable rather than self-certifying."
  },
  {
    id: "move.ref.return.observed",
    subjectKind: "sui:function",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" }
    ],
    values: ["mutable", "immutable"],
    mode: "exclusive",
    valueEncoder: "token",
    group: "move.ref.return",
    emitters: ["dynamic-trace"],
    meaning: "What the resolved signature of this call returned in this transaction."
  },
  {
    id: "move.ref.return.declared",
    subjectKind: "sui:function",
    args: [{ name: "package", encoder: "hexaddress" }],
    values: ["mutable", "immutable"],
    mode: "exclusive",
    valueEncoder: "token",
    group: "move.ref.return",
    emitters: ["static-source"],
    meaning: "What the declared return type of this function is in the source."
  },
  {
    id: "move.balance.delta",
    subjectKind: "sui:address-coin",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" }
    ],
    values: null,
    mode: "distinct",
    valueEncoder: "signeddecimal",
    group: null,
    emitters: ["dynamic-trace"],
    meaning: "The net coin movement for one address and coin type in this transaction."
  },
  {
    id: "move.ptb.calls",
    subjectKind: "sui:package-module",
    args: [
      { name: "network", encoder: "network" },
      { name: "digest", encoder: "txdigest" }
    ],
    values: null,
    mode: "distinct",
    valueEncoder: "csvsorted",
    group: null,
    emitters: ["dynamic-trace"],
    meaning: "The command indices at which this module was called in this transaction."
  },
  {
    id: "move.function.signature",
    subjectKind: "sui:function",
    args: [{ name: "package", encoder: "hexaddress" }],
    values: null,
    mode: "distinct",
    valueEncoder: "uri",
    group: null,
    emitters: ["static-source"],
    meaning: "The canonical parameter-and-return list of a function, as read from the source."
  },
  {
    id: "move.value.control",
    subjectKind: "sui:function",
    args: [{ name: "package", encoder: "hexaddress" }],
    values: ["caller", "internal"],
    mode: "exclusive",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace", "static-source"],
    assertEmitters: ["static-source"],
    meaning: "Whether the value this function mutates or returns arrives from the caller's parameter list or is reached inside the module. This is a Move-source question: a transaction trace cannot answer it, which is precisely why a dynamic finding that rests on it carries it as an assumption and can be silenced by a tool that read the source."
  },
  {
    id: "move.finding.signal",
    subjectKind: "sui:transaction",
    args: [{ name: "network", encoder: "network" }],
    values: null,
    mode: "distinct",
    valueEncoder: "token",
    group: null,
    emitters: ["dynamic-trace", "static-source", "imported"],
    collidable: false,
    meaning: "That a detector fired, carrying its severity signal and limits. Deliberately outside the algebra: a detector firing is a fact about the tool, not a fact about the transaction, and two detectors disagreeing about a label must not compose into a contradiction."
  }
];

/**
 * Cross-predicate collision. Two tools that model the same fact under different predicate ids can
 * only collide inside a declared group — never because a name looked similar.
 *
 * The cost is stated plainly: this table is curated by hand, and a typo in it silently re-enables
 * either fabricated agreement or a missed contradiction. The conformance gate exists for that.
 */
export interface ConflictGroup {
  id: string;
  domain: readonly string[];
  predicates: readonly string[];
}

export const CONFLICT_GROUPS: readonly ConflictGroup[] = [
  {
    id: "move.ref.return",
    domain: ["mutable", "immutable"],
    predicates: ["move.ref.return.observed", "move.ref.return.declared"]
  }
];

const BY_ID = new Map(PREDICATES.map((p) => [p.id, p]));

export function registryVersion(): string {
  return `${REGISTRY_NAME}@${REGISTRY_MAJOR}`;
}

export function lookupPredicate(id: string, major: number = REGISTRY_MAJOR): PredicateDef {
  if (major !== REGISTRY_MAJOR) throw new UnknownRegistryError(major, REGISTRY_MAJOR);
  const def = BY_ID.get(id);
  if (!def) throw new UnknownPredicateError(id, major);
  return def;
}

export function conflictGroup(id: string): ConflictGroup | null {
  return CONFLICT_GROUPS.find((g) => g.id === id) ?? null;
}

export function groupForPredicate(predicateId: string): ConflictGroup | null {
  const def = BY_ID.get(predicateId);
  return def?.group ? conflictGroup(def.group) : null;
}

/** Validates a value against a predicate's declared domain, or refuses. */
export function assertValue(def: PredicateDef, value: string): void {
  if (def.values === null) return;
  if (!def.values.includes(value)) throw new UnknownValueError(def.id, value);
}

/** The domain that governs a pair, or null when the pair cannot collide. */
export interface ConflictSpace {
  /** Names the space so a report can say *what* two claims disagreed about. */
  space: string;
  /** null means an open domain: any two different values are a dispute. */
  domain: readonly string[] | null;
}

export function sharedConflictSpace(a: PredicateDef, b: PredicateDef): ConflictSpace | null {
  if (!isCollidable(a) || !isCollidable(b)) return null;
  if (a.id === b.id) return { space: a.id, domain: a.values };
  if (!a.group || !b.group || a.group !== b.group) return null;
  const group = conflictGroup(a.group);
  if (!group) throw new MalformedClaimError(`Predicate pair references undeclared conflict group "${a.group}".`);
  if (!group.predicates.includes(a.id) || !group.predicates.includes(b.id)) return null;
  return { space: group.id, domain: group.domain };
}

/**
 * Conflict inside a space. A null domain is an open one, where "different" is the whole relation.
 * Values outside the declared domain are refused rather than treated as merely unequal — otherwise a
 * typo in a token would manufacture a contradiction out of nothing.
 */
export function spaceValuesConflict(domain: readonly string[] | null, a: string, b: string): boolean {
  if (a === b) return false;
  if (domain === null) return true;
  if (!domain.includes(a) || !domain.includes(b)) {
    throw new UnknownValueError(`space(${domain.join("|")})`, domain.includes(a) ? b : a);
  }
  return true;
}

export function subjectKindOf(id: string): SubjectKind {
  return lookupPredicate(id).subjectKind;
}
