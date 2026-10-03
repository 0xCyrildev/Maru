/**
 * A local, read-only mirror of Chase 0.3.0's wire shapes. Chase is not a dependency of Maru and is
 * not modified by it: the adapter consumes the JSON Chase already emits (`analyze --json`,
 * `triage --json`, batch ndjson) and the cached trace shape that input is built from.
 *
 * The shapes are mirrored rather than imported so that a change in Chase is a *detected* drift at
 * conformance time instead of a compile error in a package that ships independently.
 */
export type ChaseSeverity = "low" | "medium" | "high" | "critical";

/** `unresolved` = looked and could not classify. `unrecorded` = nobody looked. They are not the same statement. */
export type ChaseOwnerKind =
  | "address"
  | "consensus-address"
  | "object"
  | "immutable"
  | "shared"
  | "unresolved"
  | "unrecorded";

export interface ChaseViolation {
  type: string;
  severity: ChaseSeverity;
  message: string;
  /** Parsed JSON, so "absent" and "present-and-null" are both possible; `| undefined` is deliberate under exactOptionalPropertyTypes. */
  evidence?: Record<string, unknown> | undefined;
}

export interface ChaseAnalysisReport {
  digest: string;
  network: string;
  timestamp: string;
  sender: string;
  success: boolean;
  violations: ChaseViolation[];
  detectorErrors: string[];
  stats: {
    balanceChanges: number;
    objectChanges: number;
    ptbCommands: number;
    events: number;
    silentObjectChanges: number;
  };
}

export interface ChaseObjectChange {
  objectId: string;
  objectType: string;
  changeType: string;
  recipient?: string | undefined;
  sender?: string | undefined;
  outputOwnerKind?: ChaseOwnerKind | undefined;
  outputOwnerId?: string | undefined;
}

export interface ChasePtbCommand {
  index: number;
  kind: string;
  packageId?: string | undefined;
  module?: string | undefined;
  function?: string | undefined;
  /** Absent on a non-MoveCall; present-and-absent on a MoveCall means the signature could not be resolved. */
  returnsMutableRef?: boolean | undefined;
}

export interface ChaseBalanceChange {
  owner: string;
  coinType: string;
  amount: string | number;
}

export interface ChaseEvent {
  type: string;
  packageId: string;
  module: string;
  sender: string;
  parsedJson: Record<string, unknown>;
}

export interface ChaseTrace {
  digest: string;
  network?: string | undefined;
  sender: string;
  success: boolean;
  balanceChanges: ChaseBalanceChange[];
  objectChanges: ChaseObjectChange[];
  ptbCommands: ChasePtbCommand[];
  events: ChaseEvent[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function arr(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function parseAnalysisReport(raw: unknown): ChaseAnalysisReport {
  if (!isRecord(raw)) throw new Error("Chase report must be a JSON object.");
  const digest = str(raw.digest);
  const network = str(raw.network);
  if (!digest || !network) throw new Error("Chase report is missing `digest` or `network`.");
  const stats = isRecord(raw.stats) ? raw.stats : {};
  return {
    digest,
    network,
    timestamp: str(raw.timestamp) ?? "",
    sender: str(raw.sender) ?? "",
    success: raw.success === true,
    violations: arr(raw.violations).map((v) => {
      if (!isRecord(v) || typeof v.type !== "string" || typeof v.severity !== "string") {
        throw new Error("Chase violation is missing `type` or `severity`.");
      }
      return {
        type: v.type,
        severity: v.severity as ChaseSeverity,
        message: str(v.message) ?? "",
        evidence: isRecord(v.evidence) ? v.evidence : undefined
      };
    }),
    detectorErrors: arr(raw.detectorErrors).map((e) => String(e)),
    stats: {
      balanceChanges: Number(stats.balanceChanges ?? 0),
      objectChanges: Number(stats.objectChanges ?? 0),
      ptbCommands: Number(stats.ptbCommands ?? 0),
      events: Number(stats.events ?? 0),
      silentObjectChanges: Number(stats.silentObjectChanges ?? 0)
    }
  };
}

export function parseTrace(raw: unknown): ChaseTrace {
  if (!isRecord(raw)) throw new Error("Chase trace must be a JSON object.");
  const digest = str(raw.digest);
  if (!digest) throw new Error("Chase trace is missing `digest`.");
  return {
    digest,
    network: str(raw.network) ?? undefined,
    sender: str(raw.sender) ?? "",
    success: raw.success !== false,
    balanceChanges: arr(raw.balanceChanges).map((b) => {
      if (!isRecord(b)) throw new Error("Balance change row is not an object.");
      return { owner: str(b.owner) ?? "", coinType: str(b.coinType) ?? "", amount: (b.amount as string | number) ?? "0" };
    }),
    objectChanges: arr(raw.objectChanges).map((o) => {
      if (!isRecord(o)) throw new Error("Object change row is not an object.");
      // Chase's JSON writes `outputOwnerKind: null` for a row whose owner was never captured. That is
      // `unrecorded`, not a value — treating the null as an unknown kind would invent a third statement.
      const ownerKind = typeof o.outputOwnerKind === "string" ? (o.outputOwnerKind as ChaseOwnerKind) : undefined;
      return {
        objectId: str(o.objectId) ?? "",
        objectType: str(o.objectType) ?? "",
        changeType: str(o.changeType) ?? "",
        recipient: str(o.recipient) ?? undefined,
        sender: str(o.sender) ?? undefined,
        outputOwnerKind: ownerKind,
        outputOwnerId: str(o.outputOwnerId) ?? undefined
      };
    }),
    ptbCommands: arr(raw.ptbCommands).map((c) => {
      if (!isRecord(c)) throw new Error("PTB command row is not an object.");
      return {
        index: Number(c.index),
        kind: str(c.kind) ?? "",
        packageId: str(c.packageId) ?? undefined,
        module: str(c.module) ?? undefined,
        function: str(c.function) ?? undefined,
        returnsMutableRef: typeof c.returnsMutableRef === "boolean" ? c.returnsMutableRef : undefined
      };
    }),
    events: arr(raw.events).map((e) => {
      if (!isRecord(e)) throw new Error("Event row is not an object.");
      return {
        type: str(e.type) ?? "",
        packageId: str(e.packageId) ?? "",
        module: str(e.module) ?? "",
        sender: str(e.sender) ?? "",
        parsedJson: isRecord(e.parsedJson) ? e.parsedJson : {}
      };
    })
  };
}
