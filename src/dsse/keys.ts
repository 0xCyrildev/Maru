import crypto from "node:crypto";
import { MalformedClaimError } from "../lib/errors.js";

export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

/**
 * A key is identified by its own JWK thumbprint (RFC 7638: SHA-256 over the lexicographically ordered
 * required members, base64url without padding), prefixed so a Maru keyid cannot be confused with a
 * kid from some other system. Identity is derived from the key, never from a name — a tool that
 * claims to be `chase` is not `chase` until a pinned key says so.
 */
export function keyIdForJwk(jwk: Ed25519Jwk): string {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || jwk.x.length === 0) {
    throw new MalformedClaimError(`Not an Ed25519 public JWK: ${JSON.stringify(jwk)}`);
  }
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`;
  const digest = crypto.createHash("sha256").update(canonical, "utf8").digest("base64url");
  return `maru:${digest}`;
}

export function publicKeyFromJwk(jwk: Ed25519Jwk): crypto.KeyObject {
  return crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKey, format: "jwk" });
}

export function jwkFromPublicKey(key: crypto.KeyObject): Ed25519Jwk {
  const exported = key.export({ format: "jwk" }) as crypto.JsonWebKey;
  if (exported.kty !== "OKP" || exported.crv !== "Ed25519" || typeof exported.x !== "string") {
    throw new MalformedClaimError("Exported key is not an Ed25519 public JWK.");
  }
  return { kty: "OKP", crv: "Ed25519", x: exported.x };
}

export interface GeneratedKey {
  keyId: string;
  jwk: Ed25519Jwk;
  privatePem: string;
}

export function generateKey(): GeneratedKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = jwkFromPublicKey(publicKey);
  return {
    keyId: keyIdForJwk(jwk),
    jwk,
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

/**
 * A key from a 32-byte seed. This exists only so conformance fixtures can sign reproducibly: their
 * seeds are committed and therefore public, which makes them worthless as trust anchors and perfectly
 * good as tests. `maru key generate` is the only path to a key anyone should rely on.
 */
export function privateKeyFromSeed(seedHex: string): crypto.KeyObject {
  if (!/^[0-9a-f]{64}$/.test(seedHex)) throw new MalformedClaimError("Fixture seed must be 32 bytes of lowercase hex.");
  const der = Buffer.from(PKCS8_ED25519_PREFIX + seedHex, "hex");
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function publicKeyOf(privateKey: crypto.KeyObject): Ed25519Jwk {
  return jwkFromPublicKey(crypto.createPublicKey(privateKey));
}

export function signBytes(privateKey: crypto.KeyObject, bytes: Uint8Array): Buffer {
  return crypto.sign(null, bytes, privateKey);
}

export function verifyBytes(jwk: Ed25519Jwk, bytes: Uint8Array, signature: Uint8Array): boolean {
  return crypto.verify(null, bytes, publicKeyFromJwk(jwk), signature);
}
