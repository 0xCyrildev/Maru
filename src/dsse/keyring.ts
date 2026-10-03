import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { UnregisteredKeyError } from "../lib/errors.js";
import { keyIdForJwk, type Ed25519Jwk } from "./keys.js";

export interface KeyringEntry {
  toolId: string;
  keyId: string;
  jwk: Ed25519Jwk;
  addedAt: string;
  /** Who pinned it and why. Trust here is local and auditable, which is the whole point of not building PKI in v0. */
  note: string;
}

export interface Keyring {
  maruKeyring: "maru/keyring/v1";
  entries: KeyringEntry[];
}

export const EMPTY_KEYRING: Keyring = { maruKeyring: "maru/keyring/v1", entries: [] };

export function parseKeyring(raw: unknown): Keyring {
  if (typeof raw !== "object" || raw === null) throw new Error("Keyring must be a JSON object.");
  const ring = raw as Partial<Keyring>;
  if (ring.maruKeyring !== "maru/keyring/v1") throw new Error(`Unrecognised keyring document (maruKeyring = ${JSON.stringify(ring.maruKeyring)}).`);
  const entries = ring.entries ?? [];
  for (const entry of entries) {
    const derived = keyIdForJwk(entry.jwk);
    if (derived !== entry.keyId) {
      throw new Error(
        `Keyring entry for "${entry.toolId}" records keyid ${entry.keyId} but its JWK hashes to ${derived}. The entry was hand-edited; refusing to trust a mismatched pairing.`
      );
    }
  }
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.keyId)) throw new Error(`Duplicate keyid in keyring: ${entry.keyId}`);
    seen.add(entry.keyId);
  }
  return { maruKeyring: "maru/keyring/v1", entries };
}

export function loadKeyring(path: string): Keyring {
  if (!existsSync(path)) return EMPTY_KEYRING;
  return parseKeyring(JSON.parse(readFileSync(path, "utf8")));
}

export function findKey(ring: Keyring, keyId: string): KeyringEntry {
  const entry = ring.entries.find((e) => e.keyId === keyId);
  if (!entry) throw new UnregisteredKeyError(keyId);
  return entry;
}

export function toolsIn(ring: Keyring): string[] {
  return [...new Set(ring.entries.map((e) => e.toolId))].sort();
}

export function saveKeyring(ring: Keyring, path: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify({ ...ring, entries: [...ring.entries].sort((a, b) => a.keyId.localeCompare(b.keyId)) }, null, 2)}\n`, "utf8");
}

/** Trust here is a human pasting a key into a file they read, which is the whole design in v0. */
export function withEntry(ring: Keyring, entry: KeyringEntry): Keyring {
  const rest = ring.entries.filter((e) => e.keyId !== entry.keyId);
  return parseKeyring({ maruKeyring: "maru/keyring/v1", entries: [...rest, entry] });
}

export function withoutKey(ring: Keyring, keyId: string): { ring: Keyring; dropped: KeyringEntry | null } {
  const entry = ring.entries.find((e) => e.keyId === keyId) ?? null;
  if (!entry) return { ring, dropped: null };
  return { ring: parseKeyring({ maruKeyring: "maru/keyring/v1", entries: ring.entries.filter((e) => e.keyId !== keyId) }), dropped: entry };
}
