import { MalformedClaimError } from "./errors.js";

/**
 * The only canonicalization in Maru. Identity is computed over a fixed projection — a tuple with a
 * declared argument order and one encoder per argument — never over arbitrary evidence.
 *
 * DSSE deliberately avoids depending on canonicalization, and Maru inherits that stance: JS objects
 * cannot be safely canonicalized across tools (key presence varies with data, bigints stringify two
 * ways, prose lives inside structured fields). So instead of pretending the whole finding is
 * hashable, Maru hashes a projection it can pin and names every field it could not.
 */
export type EncoderName =
  | "network"
  | "hexaddress"
  | "digest"
  | "txdigest"
  | "decimal"
  | "signeddecimal"
  | "token"
  | "typestring"
  | "csvsorted"
  | "uri";

const NETWORKS = new Set(["mainnet", "testnet", "devnet", "localnet"]);
const HEX64 = /^0x[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const SIGNED_DECIMAL = /^-?(0|[1-9][0-9]*)$/;
const CONTROL = /[\x00-\x1f\x7f]/;

/** Move/Sui type strings are structured; keep the grammar loose but the *encoding* strict. */
const TYPESTRING = /^[A-Za-z0-9_$]+(?:::[A-Za-z0-9_$]+){0,2}(<[^<>]{0,512}>)?$/;

/** Sui transaction digests are base58 — case-sensitive, so they are never lowercased. */
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{30,60}$/;

function refuse(what: string, value: string, where: string): never {
  throw new MalformedClaimError(`${what} failed for "${value}" (${where}).`);
}

/** Every encoder's output must be safe as one subject part: no separator byte, ever. */
function assertPartSafe(value: string, where: string): string {
  if (value.includes(SUBJECT_SEP)) refuse("subject part without the | separator", value, where);
  return value;
}

/**
 * Every encoder maps a raw input to exactly one canonical string, or refuses. Determinism is the
 * whole contract: two encoders disagreeing about "0x0A" vs "0x0a" silently splits one claim into
 * two, which reads as "the finding disappeared".
 */
export function encodeValue(encoder: EncoderName, raw: unknown, where: string): string {
  return assertPartSafe(encodeRaw(encoder, raw, where), where);
}

function encodeRaw(encoder: EncoderName, raw: unknown, where: string): string {
  if (typeof raw !== "string" && typeof raw !== "number" && !Array.isArray(raw)) {
    refuse(encoder, String(raw), where);
  }
  const text = typeof raw === "string" ? raw : Array.isArray(raw) ? raw.join(",") : String(raw);

  switch (encoder) {
    case "network": {
      if (!NETWORKS.has(text)) refuse("known network", text, where);
      return text;
    }
    case "hexaddress": {
      const lowered = text.toLowerCase();
      if (!HEX64.test(lowered)) refuse("0x + 64 hex", text, where);
      return lowered;
    }
    case "digest": {
      const lowered = text.toLowerCase();
      if (!HEX64.test(lowered)) refuse("transaction digest (0x + 64 hex)", text, where);
      return lowered;
    }
    case "txdigest": {
      if (!BASE58.test(text)) refuse("base58 transaction digest", text, where);
      return text;
    }
    case "decimal": {
      if (!DECIMAL.test(text)) refuse("non-negative canonical decimal", text, where);
      return text;
    }
    case "signeddecimal": {
      if (!SIGNED_DECIMAL.test(text)) refuse("canonical signed decimal", text, where);
      return text.startsWith("-") && text !== "-0" ? text : text.replace(/^-0$/, "0");
    }
    case "token": {
      if (CONTROL.test(text) || text.trim() !== text || text.length === 0) {
        refuse("registry token", text, where);
      }
      return text;
    }
    case "uri": {
      if (CONTROL.test(text) || text.length === 0) refuse("uri", text, where);
      return text;
    }
    case "typestring": {
      if (!TYPESTRING.test(text)) refuse("Move type string", text, where);
      return text;
    }
    case "csvsorted": {
      const items = Array.isArray(raw) ? raw.map((x) => String(x)) : text.split(",");
      for (const item of items) {
        if (item.length === 0) refuse("non-empty csv entries", text, where);
        if (item.includes(",")) refuse("entries without commas", item, where);
        if (CONTROL.test(item)) refuse("entries without control bytes", item, where);
      }
      const unique = [...new Set(items)].sort();
      return unique.join(",");
    }
  }
}

/**
 * Subjects are namespaced so a Sui object can never collide with a file path from another toolchain.
 */
export type SubjectKind =
  | "sui:object"
  | "sui:event-type"
  | "sui:function"
  | "sui:package-module"
  | "sui:address-coin"
  | "sui:transaction";

/**
 * Subject parts are joined with `|`, never with `:`. A Move type string is `0x2::coin::Coin<0x2::sui::SUI>`
 * and a module-qualified function is `pkg::m::f`, so a colon separator makes a two-part subject look like
 * a six-part one — a bug found by running the adapter over Chase's own fixtures rather than by reading it.
 * `|` is refused by every encoder below, so the boundary stays unambiguous.
 */
const SUBJECT_SEP = "|";

/**
 * Each subject kind has a fixed part list with an encoder per part, so "sui:object" can never be
 * spelled two ways and a part that is not an address is refused at construction, not at compose time.
 */
export const SUBJECT_PARTS: Record<SubjectKind, { label: string; encoder: EncoderName }[]> = {
  "sui:object": [{ label: "objectId", encoder: "hexaddress" }],
  "sui:event-type": [{ label: "eventType", encoder: "typestring" }],
  "sui:function": [
    { label: "package", encoder: "hexaddress" },
    { label: "module", encoder: "token" },
    { label: "function", encoder: "token" }
  ],
  "sui:package-module": [
    { label: "package", encoder: "hexaddress" },
    { label: "module", encoder: "token" }
  ],
  "sui:address-coin": [
    { label: "address", encoder: "hexaddress" },
    { label: "coinType", encoder: "typestring" }
  ],
  "sui:transaction": [{ label: "digest", encoder: "txdigest" }]
};

/**
 * Subjects are namespaced so a Sui object can never collide with a file path from another toolchain,
 * and every part passes its kind's encoder — so an address is always lowercase 0x-hex and a module
 * name can never be empty or contain whitespace.
 */
export function buildSubjectUri(kind: SubjectKind, raw: unknown[]): string {
  const spec = SUBJECT_PARTS[kind];
  if (spec === undefined) {
    throw new MalformedClaimError(`Subject kind "${kind}" is not declared in this registry version.`);
  }
  if (raw.length !== spec.length) {
    throw new MalformedClaimError(
      `Subject kind "${kind}" declares ${spec.length} part(s) (${spec.map((p) => p.label).join(", ")}); got ${raw.length}.`
    );
  }
  const parts = spec.map((p, i) => encodeValue(p.encoder, raw[i] ?? "", `${kind}.${p.label}`));
  return `${kind}:${parts.join(SUBJECT_SEP)}`;
}

export function parseSubjectUri(uri: string): { kind: SubjectKind; parts: string[] } {
  const kinds = Object.keys(SUBJECT_PARTS) as SubjectKind[];
  const kind = kinds.find((k) => uri.startsWith(k + ":"));
  if (!kind) {
    throw new MalformedClaimError(`Subject URI "${uri}" is not in a declared namespace (expected one of ${kinds.join(", ")}).`);
  }
  const spec = SUBJECT_PARTS[kind];
  const body = uri.slice(kind.length + 1);
  const parts = body.split(SUBJECT_SEP);
  if (parts.length !== spec.length || parts.some((p) => p.length === 0)) {
    throw new MalformedClaimError(
      `Subject URI "${uri}" has ${parts.length} part(s) (${spec.map((p) => p.label).join(", ")}) but kind "${kind}" declares ${spec.length}. Refusing rather than matching a malformed subject against the wrong one.`
    );
  }
  return { kind, parts };
}
