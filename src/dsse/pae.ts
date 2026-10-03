/**
 * DSSE Pre-Authentication Encoding (PAEv1), exactly as the in-toto envelope spec defines it:
 *
 *   PAE(type, data) = "DSSEv1" SP LEN(type) SP type SP LEN(data) SP data
 *
 * Lengths are byte counts of the UTF-8 bytes, in decimal, no padding. The point of PAE is that the
 * type is part of what is signed, so a signature over a Maru statement can never be replayed as a
 * signature over some other payload type. Maru also inherits DSSE's stance on canonicalization: the
 * payload bytes are signed as they are, so no JSON canonicalizer is ever in the trust path.
 */
export const DSSE_PAETYPE = "DSSEv1";

export function pae(payloadType: string, payload: Uint8Array): Buffer {
  const chunks: Buffer[] = [
    Buffer.from(DSSE_PAETYPE, "ascii"),
    Buffer.from(" ", "ascii"),
    Buffer.from(String(Buffer.from(payloadType, "utf8").length), "ascii"),
    Buffer.from(" ", "ascii"),
    Buffer.from(payloadType, "utf8"),
    Buffer.from(" ", "ascii"),
    Buffer.from(String(payload.length), "ascii"),
    Buffer.from(" ", "ascii"),
    Buffer.from(payload)
  ];
  return Buffer.concat(chunks);
}
