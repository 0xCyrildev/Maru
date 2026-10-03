/**
 * Every refusal is a typed error with a stable code. Maru never guesses a value it does not model:
 * an unregistered predicate, an unknown registry major, an unkeyed signature or an unmodelled token
 * stops the run rather than coercing to a default. A quiet default is how a protocol starts
 * reporting agreement it never observed.
 */
export class MaruError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class MalformedClaimError extends MaruError {
  constructor(message: string) {
    super("MALFORMED_CLAIM", message);
  }
}

export class UnknownPredicateError extends MaruError {
  constructor(id: string, major: number) {
    super(
      "UNKNOWN_PREDICATE",
      `Predicate "${id}" is not in registry core@${major}. Refusing: guessing a complement relation for an unregistered predicate would report a collision that was never declared.`
    );
  }
}

export class UnknownRegistryError extends MaruError {
  constructor(claimed: number, supported: number) {
    super(
      "UNKNOWN_REGISTRY_MAJOR",
      `Claim requires registry major ${claimed}; this build speaks core@${supported}. Refusing rather than interpreting a complement relation under a different registry.`
    );
  }
}

export class UnknownValueError extends MaruError {
  constructor(predicateId: string, value: string) {
    super(
      "UNKNOWN_VALUE",
      `Value "${value}" is outside the declared domain of predicate "${predicateId}". Refusing rather than treating an unmodelled token as a normal one.`
    );
  }
}

export class UnknownEmitterError extends MaruError {
  constructor(kind: string) {
    super("UNKNOWN_EMITTER_KIND", `Emitter kind "${kind}" is not declared in the registry.`);
  }
}

export class UnregisteredKeyError extends MaruError {
  constructor(keyId: string) {
    super(
      "UNREGISTERED_KEY",
      `Key "${keyId}" is not in the pinned keyring. The signature may well be valid; nobody has said who it belongs to, so it is not attributable.`
    );
  }
}

export class SignatureError extends MaruError {
  constructor(keyId: string) {
    super("SIGNATURE_INVALID", `Signature from key "${keyId}" does not verify over the payload bytes.`);
  }
}

export class ProjectionMismatchError extends MaruError {
  constructor(claimId: string, recomputed: string) {
    super(
      "PROJECTION_MISMATCH",
      `claimId "${claimId}" does not match the projection recomputed from this claim ("${recomputed}"). The claim's identity fields were edited after signing, or the adapter's encoders changed — a drifted claimId reads exactly like a finding that vanished.`
    );
  }
}


export class ToolKeyMismatchError extends MaruError {
  constructor(claimedTool: string, keyTool: string, keyId: string) {
    super(
      "TOOL_KEY_MISMATCH",
      `Claim says it came from "${claimedTool}" but the signing key "${keyId}" is pinned to "${keyTool}". Identity is the key, never the name — otherwise any tool could borrow a trusted one's label.`
    );
  }
}

