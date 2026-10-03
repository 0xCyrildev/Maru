/** Emitter #2's identity. Its key, not its name, is what makes its claims attributable. */
export const STATIC_TOOL = {
  id: "move-static",
  version: "0.0.1",
  check: "signature-and-handle-supply"
} as const;
