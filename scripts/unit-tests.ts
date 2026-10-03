import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

import { assertClaimId, buildClaim, type Claim, type ClaimInput } from "../src/envelope/claim.js";
import { MaruError } from "../src/lib/errors.js";
import { buildSubjectUri, encodeValue, type SubjectKind } from "../src/lib/encode.js";
import { claimIdFromProjection, lineageKeyFromFacet, projectClaim } from "../src/ids/claim.js";
import { PREDICATES, lookupPredicate, type EmitterKind } from "../src/registry/core.js";
import { generateKey, keyIdForJwk, type Ed25519Jwk } from "../src/dsse/keys.js";
import { DSSE_PAETYPE, pae } from "../src/dsse/pae.js";
import { signStatement } from "../src/dsse/sign.js";
import { verifyEnvelope } from "../src/dsse/verify.js";
import { parseKeyring } from "../src/dsse/keyring.js";
import { parseStatement, toStatement } from "../src/envelope/statement.js";
import { chaseToClaims } from "../src/adapters/chase/index.js";
import { parseAnalysisReport, parseTrace } from "../src/adapters/chase/wire.js";
import { EMISSIONS, REPORT_ONLY_TYPES, driftCheck } from "../src/adapters/chase/methodology.js";
import { claimsFromSource } from "../src/emitters/move-static/index.js";
import { exportSarif, importSarif } from "../src/adapters/sarif/index.js";
import { compose, compositionStatement } from "../src/ops/compose.js";
import { topicOf } from "../src/ops/join.js";
import { runGates } from "../conformance/gates.js";
import type { CompositionResult } from "../src/ops/compose.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
// Vendored, so a fresh clone needs nothing else on disk; see test/fixtures/NOTICE.md for provenance.
const CORPUS = process.env.CHRASE_CORPUS ?? join(root, "test/fixtures/synthetic-leak/sources");
const EMITTED_AT = "2026-10-02T00:00:00.000Z";

function commandRm(path: string): void {
  // Recursive, and never the shell's `rm`: it is aliased to -i here, so a non-interactive call prompts,
  // reads nothing, leaves the file — while the surrounding chain still reports success.
  rmSync(path, { force: true, recursive: true, maxRetries: 3 });
}

const results: { name: string; error: string | null }[] = [];
const skips: string[] = [];

function test(name: string, fn: () => void): void {
  try {
    fn();
    results.push({ name, error: null });
  } catch (error) {
    results.push({ name, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) });
  }
}

function expectCode(code: string, fn: () => unknown): void {
  let seen: unknown = null;
  try {
    fn();
  } catch (error) {
    seen = error;
  }
  assert.ok(seen instanceof MaruError, `expected MaruError ${code}, got ${String(seen)}`);
  assert.equal((seen as MaruError).code, code);
}

const chaseMethodology = {
  tool: "chase",
  toolVersion: "0.3.0",
  check: "unit-test",
  checkVersion: "0.0.0",
  emitter: "dynamic-trace" as const
};

const OBJ_A = "0x56b65b125b29e6bcfd1cf8dc4bcc0c2e79325684cbad401dfbff75ea0ba862f7";
const OBJ_B = "0x15e3cd7582f1d2709e3029bedff44bf8220dcd99a7ac6a31c630721361e1169e";
const ADDR = "0x4e7a16d751af45ed7741b6a83992ab2af92e3706b43330757a84c2cb6deb7e85";
const PKG_LEAK = "0x10172126bb0bc55e32dea70a223b7590da2eecf6a1b40bb2c353f1d750f12405";
const DIGEST_LEAK = "9gwFpqxGmnfUyu8ciiEHHKHmWw42vMJddD6PpUuGLkKg";
const LEAK_FN = buildSubjectUri("sui:function", [PKG_LEAK, "leak", "leak_mut"]);

function makeClaim(over: ClaimInput): Claim {
  return buildClaim(over);
}

function ownershipClaim(objectId: string, value: string, over: Partial<ClaimInput> = {}): Claim {
  return makeClaim({
    channel: "assert",
    predicate: "move.object.ownership",
    subjectKind: "sui:object",
    subject: [objectId],
    args: { network: "mainnet" },
    value,
    facet: `object:${objectId}`,
    lineageBasis: "derived",
    witness: "eligible",
    provenance: "deterministic",
    methodology: chaseMethodology,
    target: { kind: "object", network: "mainnet", digest: null },
    severitySignal: "informational",
    emittedAt: EMITTED_AT,
    ...over
  });
}

function sampleClaim(
  predicate: string,
  parts: {
    subjectKind: SubjectKind;
    subject: unknown[];
    args: Record<string, unknown>;
    value: unknown;
    emitter?: EmitterKind;
    channel?: "assert" | "assume";
    witness?: "eligible" | "report-only";
    provenance?: ClaimInput["provenance"];
    facet?: string;
    severitySignal?: ClaimInput["severitySignal"];
    unverifiableFields?: ClaimInput["unverifiableFields"];
    target?: ClaimInput["target"];
  }
): Claim {
  return makeClaim({
    channel: parts.channel ?? "assert",
    predicate,
    subjectKind: parts.subjectKind,
    subject: parts.subject,
    args: parts.args,
    value: parts.value,
    facet: parts.facet ?? `sample:${predicate}`,
    lineageBasis: "derived",
    witness: parts.witness ?? "eligible",
    provenance: parts.provenance ?? "deterministic",
    methodology: { ...chaseMethodology, emitter: parts.emitter ?? "dynamic-trace" },
    target: parts.target ?? { kind: "transaction", network: "mainnet", digest: DIGEST_LEAK },
    severitySignal: parts.severitySignal ?? "informational",
    ...(parts.unverifiableFields ? { unverifiableFields: parts.unverifiableFields } : {}),
    emittedAt: EMITTED_AT
  });
}

// ------------------------------------------------------------------ identity

test("claimId is byte-stable and depends only on the projection", () => {
  const a = ownershipClaim(OBJ_A, "shared");
  assert.equal(a.claimId, ownershipClaim(OBJ_A, "shared").claimId);
  assert.equal(a.claimId.length, 64);
  assert.notEqual(a.claimId, ownershipClaim(OBJ_A, "address").claimId);
  assert.notEqual(a.claimId, ownershipClaim(OBJ_B, "shared").claimId);

  const rerated = ownershipClaim(OBJ_A, "shared", {
    severitySignal: "critical",
    evidence: { extra: "x" },
    emittedAt: "2027-01-01T00:00:00.000Z"
  });
  assert.equal(rerated.claimId, a.claimId, "re-rating must not renumber a finding");
});

test("channel is part of identity: an assumption and an assertion are different statements", () => {
  const asserted = ownershipClaim(OBJ_A, "shared");
  const assumed = ownershipClaim(OBJ_A, "shared", { channel: "assume", witness: "report-only" });
  assert.notEqual(asserted.claimId, assumed.claimId);
});

test("assertClaimId recomputes identity and catches a field edited after signing", () => {
  const claim = ownershipClaim(OBJ_A, "shared");
  assertClaimId(claim);
  expectCode("PROJECTION_MISMATCH", () => assertClaimId({ ...claim, value: "address" }));
  expectCode("PROJECTION_MISMATCH", () => assertClaimId({ ...claim, claimId: "0".repeat(64) }));
});

test("the projection cannot be ambiguous between no arguments and one empty argument", () => {
  const none = projectClaim({ registryMajor: 1, predicate: "p", subjectUri: "s", argsOrdered: [], value: "v", channel: "assert" });
  const empty = projectClaim({ registryMajor: 1, predicate: "p", subjectUri: "s", argsOrdered: [""], value: "v", channel: "assert" });
  assert.notEqual(claimIdFromProjection(none), claimIdFromProjection(empty));
});

test("lineage is a facet hash, so identity and independence stay separate questions", () => {
  assert.equal(lineageKeyFromFacet("a|1"), lineageKeyFromFacet("a|1"));
  assert.notEqual(lineageKeyFromFacet("a|1"), lineageKeyFromFacet("b|1"));
});

// ------------------------------------------------------------------ encoders and refusals

test("encoders normalize or refuse; they never coerce quietly", () => {
  assert.equal(encodeValue("hexaddress", OBJ_A.toUpperCase(), "t"), OBJ_A);
  assert.equal(encodeValue("csvsorted", ["3", "1", "3", "2"], "t"), "1,2,3");
  assert.equal(encodeValue("signeddecimal", "-0", "t"), "0");
  assert.equal(encodeValue("signeddecimal", 5, "t"), "5");
  assert.equal(encodeValue("txdigest", DIGEST_LEAK, "t"), DIGEST_LEAK);
  assert.throws(() => encodeValue("hexaddress", "0x123", "t"));
  assert.throws(() => encodeValue("csvsorted", ["a,b"], "t"));
  assert.throws(() => encodeValue("network", "mainnet1", "t"));
  assert.throws(() => encodeValue("txdigest", `${DIGEST_LEAK}!`, "t"));
  assert.throws(() => encodeValue("token", "has|separator", "t"), "a subject part must not contain the separator");
});

test("the registry refuses what it does not model", () => {
  expectCode("UNKNOWN_PREDICATE", () =>
    sampleClaim("move.not.a.predicate", { subject: [OBJ_A], args: { network: "mainnet" }, value: "shared", subjectKind: "sui:object" })
  );
  expectCode("UNKNOWN_REGISTRY_MAJOR", () => ownershipClaim(OBJ_A, "shared", { registryMajor: 2 }));
  expectCode("UNKNOWN_VALUE", () => ownershipClaim(OBJ_A, "unresolved"));
  expectCode("MALFORMED_CLAIM", () =>
    sampleClaim("move.object.ownership", { subject: [OBJ_A], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "shared", subjectKind: "sui:object" })
  );
  expectCode("MALFORMED_CLAIM", () =>
    sampleClaim("move.object.ownership", { subject: [OBJ_A], args: {}, value: "shared", subjectKind: "sui:object" })
  );
  expectCode("MALFORMED_CLAIM", () =>
    sampleClaim("move.object.ownership", { subject: [PKG_LEAK, "leak", "leak_mut"], args: { network: "mainnet" }, value: "shared", subjectKind: "sui:function" })
  );
});

test("assumptions cannot witness, and a trace cannot assert what only source can determine", () => {
  expectCode("MALFORMED_CLAIM", () =>
    sampleClaim("move.value.control", {
      subject: [PKG_LEAK, "leak", "leak_mut"],
      args: { package: PKG_LEAK },
      value: "internal",
      subjectKind: "sui:function",
      channel: "assume",
      witness: "eligible"
    })
  );
  expectCode("MALFORMED_CLAIM", () =>
    sampleClaim("move.value.control", {
      subject: [PKG_LEAK, "leak", "leak_mut"],
      args: { package: PKG_LEAK },
      value: "internal",
      subjectKind: "sui:function",
      emitter: "dynamic-trace"
    })
  );
});

test("partial verifiability downgrades a witness without deleting the claim", () => {
  const partial = sampleClaim("move.object.change", {
    subject: [OBJ_A],
    args: { network: "testnet", digest: DIGEST_LEAK },
    value: "mutated",
    subjectKind: "sui:object",
    unverifiableFields: [{ field: "parentObject", reason: "conditional" }]
  });
  assert.equal(partial.verifiability, "partial");
  assert.equal(partial.witness, "report-only");
});

// ------------------------------------------------------------------ DSSE

test("PAE binds the payload type into the signed bytes", () => {
  const payload = Buffer.from("hello", "utf8");
  const type = "application/vnd.in-toto+json";
  assert.equal(pae(type, payload).toString("utf8"), `DSSEv1 ${type.length} ${type} 5 hello`);
  assert.ok(!pae(DSSE_PAETYPE, payload).equals(pae("application/other", payload)));
});

test("sign then verify round-trips; a truncated payload, an unknown key and an edited field all fail", () => {
  const key = generateKey();
  const jwk: Ed25519Jwk = key.jwk;
  assert.equal(keyIdForJwk(jwk), key.keyId);
  const ring = parseKeyring({
    maruKeyring: "maru/keyring/v1",
    entries: [{ toolId: "chase", keyId: key.keyId, jwk, addedAt: EMITTED_AT, note: "unit test key" }]
  });

  const claim = ownershipClaim(OBJ_A, "shared");
  const envelope = signStatement(toStatement(claim), { keyId: key.keyId, privateKey: crypto.createPrivateKey(key.privatePem) });
  const verified = verifyEnvelope(envelope, ring);
  assert.equal(verified.claim.claimId, claim.claimId);
  assert.equal(verified.signer.toolId, "chase");

  const truncated = { ...envelope, payload: Buffer.from(envelope.payload, "base64").subarray(0, 5).toString("base64") };
  expectCode("MALFORMED_CLAIM", () => verifyEnvelope(truncated, ring));
  expectCode("UNREGISTERED_KEY", () => verifyEnvelope(envelope, parseKeyring({ maruKeyring: "maru/keyring/v1", entries: [] })));

  const forged = { ...envelope, signatures: [{ keyid: key.keyId, sig: Buffer.alloc(64, 7).toString("base64") }] };
  expectCode("SIGNATURE_INVALID", () => verifyEnvelope(forged, ring));

  // Re-signing a claim whose fields no longer match its own recorded identity is the case the
  // projection check exists for: the signature is valid, and the document is still a lie.
  const inconsistent = { ...claim, value: "address" };
  const resigned = signStatement(toStatement(inconsistent), { keyId: key.keyId, privateKey: crypto.createPrivateKey(key.privatePem) });
  expectCode("PROJECTION_MISMATCH", () => verifyEnvelope(resigned, ring));
});

test("a keyring entry whose JWK does not hash to its recorded keyid is refused", () => {
  const key = generateKey();
  assert.throws(() =>
    parseKeyring({
      maruKeyring: "maru/keyring/v1",
      entries: [{ toolId: "chase", keyId: "maru:hand-edited", jwk: key.jwk, addedAt: EMITTED_AT, note: "" }]
    })
  );
});

// ------------------------------------------------------------------ Chase's own fixtures

const trace = parseTrace(JSON.parse(readFileSync(join(root, "test/fixtures/leak-mut.trace.json"), "utf8")));
const report = parseAnalysisReport(JSON.parse(readFileSync(join(root, "test/fixtures/leak-mut.report.json"), "utf8")));

test("the adapter's copy of Chase's detector table still matches Chase's source", () => {
  // An unrun control is a visible result, never a pass — but it is also not a *failure*, or every clean
  // clone of this repo would report red for a missing sibling checkout that has nothing to do with Maru.
  // Loud skip by default; MARU_REQUIRE_CHASE=1 turns it red, and CI sets it where the source exists.
  const chaseSrc = process.env.CHASE_SRC ?? join(homedir(), "projects", "chase");
  const drift = driftCheck(chaseSrc);
  if (!drift.checked) {
    skips.push(`drift check NOT RUN — ${drift.reason}`);
    if (process.env.MARU_REQUIRE_CHASE === "1") {
      throw new Error("MARU_REQUIRE_CHASE=1 was set and the drift check did not run: " + drift.reason);
    }
    return;
  }
  assert.deepEqual(drift.differences, [], "the adapter's detector table has drifted from Chase's source");
});

test("the local emission table covers exactly the twelve types Chase emits", () => {
  assert.equal(Object.keys(EMISSIONS).length, 12);
  assert.equal([...REPORT_ONLY_TYPES].sort().join(","), "DYNAMIC_FIELD_CREATED,DYNAMIC_FIELD_DELETED,UNANNOUNCED_OBJECT_CHANGE");
});

test("adapting a real Chase trace and report yields facts, one signal and one premise", () => {
  const out = chaseToClaims({ trace, report, emittedAt: EMITTED_AT });
  assert.deepEqual(out.unclassified, [], "every evidence field Chase emitted must be classified");

  const signals = out.claims.filter((c) => c.predicate === "move.finding.signal");
  assert.equal(signals.length, 1);
  assert.equal(signals[0]?.value, "MUTABLE_REFERENCE_RETURNED");
  assert.equal(signals[0]?.severitySignal, "high");
  assert.ok(signals[0]?.limits.some((l) => l.id === "limit.mutable-access.signature-only"));

  const premises = out.claims.filter((c) => c.channel === "assume");
  assert.equal(premises.length, 1);
  assert.equal(premises[0]?.predicate, "move.value.control");
  assert.equal(premises[0]?.value, "internal");
  assert.equal(premises[0]?.subjectUri, LEAK_FN);

  const observed = out.claims.find((c) => c.predicate === "move.ref.return.observed");
  assert.equal(observed?.value, "mutable");
  assert.equal(observed?.verifiability, "full");

  // This trace was normalised before owners were captured, so null is unrecorded — coverage, not a value.
  const notRead = out.coverage.filter((c) => c.kind === "not-read");
  assert.equal(notRead.length, 2);
  assert.ok(notRead.every((c) => c.reason.includes("nobody looked")));
  assert.ok(!out.claims.some((c) => c.value === "unresolved" || c.value === "unrecorded"));
  assert.ok(out.notes.join(" ").includes("reverted"));
});

test("a report with no trace says it holds no facts", () => {
  const out = chaseToClaims({ report, emittedAt: EMITTED_AT });
  assert.ok(out.claims.every((c) => c.predicate === "move.finding.signal" || c.channel === "assume"));
  assert.ok(out.coverage.some((c) => c.kind === "not-read" && c.reason.includes("signals and premises only")));
});

test("created and deleted on one dynamic field is a cycle, not two assertions", () => {
  const synthetic = parseAnalysisReport({
    digest: DIGEST_LEAK,
    network: "testnet",
    timestamp: "",
    sender: ADDR,
    success: true,
    detectorErrors: [],
    stats: { balanceChanges: 0, objectChanges: 0, ptbCommands: 1, events: 0, silentObjectChanges: 0 },
    violations: [
      { type: "DYNAMIC_FIELD_CREATED", severity: "low", message: "created", evidence: { objectId: OBJ_A, keyType: "0x2::k::K", changeType: "created", note: "x" } },
      { type: "DYNAMIC_FIELD_DELETED", severity: "low", message: "deleted", evidence: { objectId: OBJ_A, keyType: "0x2::k::K", changeType: "deleted", note: "y" } }
    ]
  });
  const out = chaseToClaims({ report: synthetic, emittedAt: EMITTED_AT });
  const lifecycle = out.claims.filter((c) => c.predicate === "move.dynamicField.lifecycle");
  assert.equal(lifecycle.length, 1);
  assert.equal(lifecycle[0]?.value, "cycle");
  assert.equal(lifecycle[0]?.witness, "report-only", "Chase declares these types too common to witness; Maru inherits that");
});

// ------------------------------------------------------------------ emitter #2 and the algebra

const staticOut = claimsFromSource({
  sourceDir: CORPUS,
  network: "testnet",
  packageAddresses: { chase_test: PKG_LEAK },
  emittedAt: EMITTED_AT,
  digest: DIGEST_LEAK
});
const adapted = chaseToClaims({ trace, report, emittedAt: EMITTED_AT });
const both = [...adapted.claims, ...staticOut.claims];

test("the static emitter reads the corpus the trace was produced from", () => {
  const declared = staticOut.claims.find((c) => c.predicate === "move.ref.return.declared" && c.subjectUri === LEAK_FN);
  assert.equal(declared?.value, "mutable");
  const control = staticOut.claims.find((c) => c.predicate === "move.value.control" && c.subjectUri === LEAK_FN);
  assert.equal(control?.value, "caller");
  const signature = staticOut.claims.find((c) => c.predicate === "move.function.signature" && c.subjectUri === LEAK_FN);
  assert.equal(signature?.value, "leak::leak_mut(&mut Vault)->&mut Inner");
  assert.ok(staticOut.notes.some((n) => n.includes("undetermined")), "an undecidable handle supply must be a note, not a value");
});

test("CORROBORATE: a trace and a source reader agree on the same function", () => {
  const result = compose(both);
  const topic = `move.ref.return|${LEAK_FN}`;
  const hit = result.corroborations.find((c) => c.topic === topic);
  assert.ok(hit, `expected corroboration on ${topic}; got: ${result.corroborations.map((c) => c.topic).join(" | ") || "none"}`);
  assert.equal(hit.opinions.length, 2);
  assert.deepEqual([...new Set(hit.opinions.flatMap((o) => o.tools))].sort(), ["chase", "move-static"]);
  assert.equal(result.contradictions.length, 0);
});

test("SILENT: the source determines caller-supplied handles and falsifies the leak premise", () => {
  const result = compose(both);
  const silence = result.silences.find((s) => s.subjectUri === LEAK_FN && s.assumption.predicate === "move.value.control");
  assert.ok(silence, `expected a silent on ${LEAK_FN}`);
  assert.equal(silence.assumption.tool, "chase");
  assert.equal(silence.assertion.tool, "move-static");
  assert.equal(silence.assumption.value, "internal");
  assert.equal(silence.assertion.value, "caller");
});

test("a signal never corroborates a signal, so the overlap table has nothing to suppress", () => {
  const trio = ["FLASH_LOAN_SHAPED", "REPEATED_MODULE_CALLS", "REENTRANCY_PATTERN"].map((type) =>
    sampleClaim("move.finding.signal", {
      subject: [DIGEST_LEAK],
      args: { network: "testnet" },
      value: type,
      subjectKind: "sui:transaction",
      facet: `detector:${type}|${DIGEST_LEAK}`,
      severitySignal: "high",
      target: { kind: "transaction", network: "testnet", digest: DIGEST_LEAK }
    })
  );
  const result = compose(trio);
  assert.equal(result.corroborations.length, 0, "three labels on one transaction are not three opinions");
  assert.equal(result.contradictions.length, 0, "different labels are not a contradiction about the transaction");
  assert.equal(result.carried.length, 3);
});

test("OVERLAP: one facet holding two claims is one opinion; identical content is not overlap", () => {
  const deduped = compose([ownershipClaim(OBJ_A, "shared"), ownershipClaim(OBJ_A, "shared", { evidence: { seen: "twice" } })]);
  assert.equal(deduped.overlaps.length, 0, "identical content is one claim recorded once");
  assert.equal(deduped.corroborations.length, 0);

  const oneFacet = compose([ownershipClaim(OBJ_A, "shared"), ownershipClaim(OBJ_A, "immutable")]);
  assert.equal(oneFacet.overlaps.length, 1, "same facet, two distinct claims: one opinion, reported as overlap");
  assert.equal(oneFacet.overlaps[0]?.claimIds.length, 2);
  assert.equal(oneFacet.corroborations.length, 0, "one facet can never be two witnesses");
  assert.equal(oneFacet.contradictions.length, 1, "a tool disagreeing with itself is a dispute, not a quiet merge");

  const incomparable = compose([
    sampleClaim("move.object.change", { subject: [OBJ_A], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "mutated", subjectKind: "sui:object" }),
    ownershipClaim(OBJ_A, "shared")
  ]);
  assert.equal(incomparable.corroborations.length, 0, "different predicates on one object are incomparable, not corroborating");
});

test("CONTRADICT: a dispute blocks escalation instead of doubling as corroboration", () => {
  const result = compose([
    ownershipClaim(OBJ_A, "shared"),
    ownershipClaim(OBJ_A, "immutable", { facet: `other-tool:${OBJ_A}`, methodology: { ...chaseMethodology, tool: "other" } })
  ]);
  assert.equal(result.contradictions.length, 1);
  assert.equal(result.contradictions[0]?.nextAction, "human-review");
  const dispute = result.contradictions[0];
  assert.ok(dispute);
  assert.deepEqual([...dispute.values].sort(), ["immutable", "shared"]);
  // The pair is oriented by claimId, not by whichever claim arrived first, so the same two claims
  // always report the same dispute. Left and right must still agree with their own values.
  assert.equal(dispute.left.value, dispute.values[0]);
  assert.equal(dispute.right.value, dispute.values[1]);
  assert.ok(dispute.left.claimId.localeCompare(dispute.right.claimId) <= 0);
  assert.equal(result.corroborations.length, 0, "two opinions that cannot both hold are not two opinions");
  assert.equal(result.suppressedCorroborations.length, 1);
});

test("nothing-agreed is reported as nothing-agreed, never as agreement", () => {
  const result = compose([ownershipClaim(OBJ_A, "shared"), ownershipClaim(OBJ_B, "address")]);
  assert.equal(result.corroborations.length, 0);
  assert.equal(result.contradictions.length, 0);
  assert.equal(result.solitary.length, 2);
  assert.ok(result.headline.includes("Nothing composed"));
});

test("an unchecked assumption is listed, not silently dropped", () => {
  const lonely = sampleClaim("move.value.control", {
    subject: [PKG_LEAK, "leak", "leak_mut"],
    args: { package: PKG_LEAK },
    value: "internal",
    subjectKind: "sui:function",
    channel: "assume",
    witness: "report-only",
    provenance: "rules",
    emitter: "dynamic-trace"
  });
  const result = compose([lonely]);
  assert.equal(result.undischarged.length, 1);
  assert.ok(result.headline.includes("nobody checked"));
});

test("composition carries no escalation field at any depth", () => {
  const result = compose(both);
  const keys = new Set<string>();
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        keys.add(key);
        walk(child);
      }
    }
  };
  walk(result);
  const banned = /^(score|tier|priority|weight|rank|confidence|severity|escalat\w*)$/i;
  assert.deepEqual([...keys].filter((k) => banned.test(k)), [], "no field a consumer could count into an escalation");
  assert.ok(!keys.has("severitySignal"), "a composition result must not carry severity at all — it has none to give");

  const claimKeys = new Set<string>();
  const walkClaims = (value: unknown): void => {
    if (Array.isArray(value)) for (const item of value) walkClaims(item);
    else if (value && typeof value === "object") for (const [k, child] of Object.entries(value)) { claimKeys.add(k); walkClaims(child); }
  };
  walkClaims(both);
  assert.ok(claimKeys.has("severitySignal"), "claims keep their own severity, unchanged and unmerged");
});

test("shuffled inputs compose to the same bytes", () => {
  const stable = (r: ReturnType<typeof compose>) => JSON.stringify({ ...r, generatedAt: "" });
  assert.equal(stable(compose(both)), stable(compose([...both].reverse())));
  assert.ok(compositionStatement(compose(both)).subject[0]?.uri.startsWith("maru:composition/"));
});

test("a composition result is not a claim and is refused as one", () => {
  const statement = compositionStatement(compose(both));
  expectCode("MALFORMED_CLAIM", () => parseStatement(statement));
});

test("topics are named by conflict space, not by predicate string", () => {
  const observed = both.find((c) => c.predicate === "move.ref.return.observed");
  const declared = both.find((c) => c.predicate === "move.ref.return.declared" && c.subjectUri === LEAK_FN);
  assert.ok(observed && declared);
  assert.equal(topicOf(observed), topicOf(declared));
  assert.notEqual(
    topicOf(observed),
    topicOf(sampleClaim("move.object.change", { subject: [OBJ_A], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "mutated", subjectKind: "sui:object" }))
  );
});

test("every predicate core@1 declares is constructible, and the sample table covers the registry exactly", () => {
  const table: Record<string, { subjectKind: SubjectKind; subject: unknown[]; args: Record<string, unknown>; value: unknown; emitter: EmitterKind }> = {
    "move.object.ownership": { subjectKind: "sui:object", subject: [OBJ_A], args: { network: "mainnet" }, value: "shared", emitter: "dynamic-trace" },
    "move.object.change": { subjectKind: "sui:object", subject: [OBJ_A], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "mutated", emitter: "dynamic-trace" },
    "move.dynamicField.lifecycle": { subjectKind: "sui:object", subject: [OBJ_A], args: { network: "mainnet", digest: DIGEST_LEAK, keyType: "0x2::k::K" }, value: "cycle", emitter: "dynamic-trace" },
    "move.event.presence": { subjectKind: "sui:package-module", subject: [PKG_LEAK, "leak"], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "absent", emitter: "dynamic-trace" },
    "move.ref.return.observed": { subjectKind: "sui:function", subject: [PKG_LEAK, "leak", "leak_mut"], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "mutable", emitter: "dynamic-trace" },
    "move.ref.return.declared": { subjectKind: "sui:function", subject: [PKG_LEAK, "leak", "leak_mut"], args: { package: PKG_LEAK }, value: "mutable", emitter: "static-source" },
    "move.balance.delta": { subjectKind: "sui:address-coin", subject: [ADDR, "0x2::sui::SUI"], args: { network: "mainnet", digest: DIGEST_LEAK }, value: "-1000", emitter: "dynamic-trace" },
    "move.ptb.calls": { subjectKind: "sui:package-module", subject: [PKG_LEAK, "leak"], args: { network: "mainnet", digest: DIGEST_LEAK }, value: [2, 0, 1], emitter: "dynamic-trace" },
    "move.function.signature": { subjectKind: "sui:function", subject: [PKG_LEAK, "leak", "leak_mut"], args: { package: PKG_LEAK }, value: "leak::leak_mut(vault:&mut Vault)->&mut Inner", emitter: "static-source" },
    "move.value.control": { subjectKind: "sui:function", subject: [PKG_LEAK, "leak", "leak_mut"], args: { package: PKG_LEAK }, value: "caller", emitter: "static-source" },
    "move.finding.signal": { subjectKind: "sui:transaction", subject: [DIGEST_LEAK], args: { network: "mainnet" }, value: "MUTABLE_REFERENCE_RETURNED", emitter: "dynamic-trace" }
  };

  assert.deepEqual(
    Object.keys(table).sort(),
    PREDICATES.map((p) => p.id).sort(),
    "a predicate nobody can build is a predicate nobody tests"
  );

  for (const def of PREDICATES) {
    const s = table[def.id];
    if (!s) continue;
    const claim = sampleClaim(def.id, { ...s, witness: "report-only" });
    assertClaimId(claim);
    assert.equal(claim.value, encodeValue(def.valueEncoder, s.value, def.id));
    assert.equal(def.values === null, def.mode === "distinct", `${def.id}: an open domain is exactly a distinct-mode predicate`);
  }

  assert.equal(lookupPredicate("move.finding.signal").collidable, false);
  assert.equal(lookupPredicate("move.event.presence").assertEmitters?.join(","), "dynamic-trace");
});

test("SARIF export and import round-trip a claim, and refuse one they cannot compose", () => {
  const log = exportSarif(both, adapted.coverage);
  assert.equal(log.version, "2.1.0");
  const resultCount = log.runs.reduce((n, run) => n + run.results.length, 0);
  assert.equal(resultCount, both.length, "every claim must survive conversion");

  const imported = importSarif(log);
  assert.equal(imported.refused.length, 0);
  assert.deepEqual(imported.claims.map((c) => c.claimId).sort(), [...both.map((c) => c.claimId)].sort());
  for (const claim of imported.claims) assertClaimId(claim);

  // A real foreign SARIF result: a file-and-region finding. core@1 has no namespace for it, so it is
  // convertible for display and refused by the algebra. Silent acceptance here would be the bug.
  const foreign = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "some-scanner", version: "9.9" } },
        results: [
          {
            ruleId: "reentrancy",
            level: "error",
            message: { text: "Possible reentrancy in Vault.sol:42" },
            locations: [{ physicalLocation: { artifactLocation: { uri: "src/Vault.sol" }, region: { startLine: 42 } } }]
          }
        ]
      }
    ]
  };
  const refused = importSarif(foreign);
  assert.equal(refused.claims.length, 0);
  assert.equal(refused.refused.length, 1);
  assert.ok(refused.refused[0]?.reason.includes("no subject namespace"));

  expectCode("MALFORMED_CLAIM", () => importSarif({ version: "2.2.0", runs: [] }));
});

test("the published JSON schema and the built claim agree", () => {
  const schema = JSON.parse(readFileSync(join(root, "docs/spec/schemas/maru-claim-v1.json"), "utf8")) as {
    required: string[];
    properties: Record<string, { enum?: string[]; const?: unknown }>;
  };
  const claim = ownershipClaim(OBJ_A, "shared");
  const built = claim as unknown as Record<string, unknown>;

  const missing = schema.required.filter((key) => !(key in built));
  assert.deepEqual(missing, [], "a required schema key the implementation does not produce is a schema that validates nothing");
  const extra = Object.keys(built).filter((key) => !(key in schema.properties));
  assert.deepEqual(extra, [], "an undeclared field on the claim means the schema has fallen behind the code");

  const agree: [string, readonly string[]][] = [
    ["channel", ["assert", "assume"]],
    ["witness", ["eligible", "report-only"]],
    ["verifiability", ["full", "partial"]],
    ["provenance", ["deterministic", "rules", "model", "fallback"]],
    ["severitySignal", ["informational", "low", "medium", "high", "critical"]]
  ];
  for (const [key, values] of agree) {
    assert.deepEqual(schema.properties[key]?.enum, values, `schema enum for "${key}" drifted from the implementation`);
  }
});

test("the conformance gates can fail — a gate that never fires is worse than no gate", () => {
  const CONTROL = "__control__";
  const fired = (result: CompositionResult): Set<string> =>
    new Set(runGates([], new Map([[CONTROL, result]]), new Map([[CONTROL, []]])).filter((f) => f.gate !== "registry-covered").map((f) => f.gate));

  const clean = compose(both);
  assert.deepEqual([...fired(clean)], [], "a real composition must trip no control gate");

  // 1. corroboration from one lineage twice. join() dedupes by lineage key, so this shape cannot arise
  //    from the code today — which is exactly why the gate must be shown to catch it if it ever could.
  const dupLineage = structuredClone(clean);
  const first = dupLineage.corroborations[0];
  if (!first || first.opinions.length < 2) {
    throw new Error("control fixture lost its corroboration; the check would pass vacuously");
  }
  const [opinionA, opinionB] = first.opinions;
  if (!opinionA || !opinionB) throw new Error("control fixture lost an opinion");
  opinionB.lineageKey = opinionA.lineageKey;
  assert.ok(fired(dupLineage).has("corroboration-needs-distinct-lineage"));

  // 2. an "overlap" that is really one claim.
  const fakeOverlap = structuredClone(clean);
  fakeOverlap.overlaps.push({ relation: "overlap", topic: "t", subjectUri: "sui:object|" + "a".repeat(64), lineageKey: "k", facet: "f", claimIds: ["only-one"], note: "" });
  assert.ok(fired(fakeOverlap).has("overlap-needs-two-claims"));

  // 3. a dispute that failed to block its own topic's escalation.
  const unsuppressed = structuredClone(clean);
  const contradiction = unsuppressed.contradictions[0] ?? {
    relation: "contradict" as const,
    subjectUri: "sui:object|" + "b".repeat(64),
    space: "move.object.ownership",
    values: ["shared", "immutable"] as [string, string],
    left: { claimId: "l", predicate: "move.object.ownership", channel: "assert" as const, value: "shared", tool: "a", emitter: "dynamic-trace", provenance: "deterministic" },
    right: { claimId: "r", predicate: "move.object.ownership", channel: "assert" as const, value: "immutable", tool: "b", emitter: "dynamic-trace", provenance: "deterministic" },
    nextAction: "human-review" as const,
    note: ""
  };
  unsuppressed.contradictions = [contradiction];
  unsuppressed.corroborations.push({
    relation: "corroborate",
    topic: `${contradiction.space}|${contradiction.subjectUri}`,
    subjectUri: contradiction.subjectUri,
    opinions: contradiction.left.claimId === "l" ? [] : [],
    declaredLineage: []
  });
  assert.ok(fired(unsuppressed).has("dispute-blocks-escalation"));

  // 4. an escalation field smuggled into the output at depth.
  const withScore = structuredClone(clean);
  (withScore as unknown as Record<string, unknown>).tier = "P1";
  assert.ok(fired(withScore).has("no-escalation-field"));
});

test("an excluded claim names its real cause, not the generic one", () => {
  // buildClaim() pre-empts witness:"eligible" to report-only for partial and model claims, so a reason
  // function that tests `witness` first calls every one of them "the emitter declined to vouch" — a lie
  // in the only field that answers "why was this left out?".
  const partial = sampleClaim("move.object.change", {
    subject: [OBJ_A],
    args: { network: "testnet", digest: DIGEST_LEAK },
    value: "mutated",
    subjectKind: "sui:object",
    unverifiableFields: [{ field: "parentObject", reason: "conditional" }]
  });
  const modelled = sampleClaim("move.object.ownership", {
    subject: [OBJ_B],
    args: { network: "mainnet" },
    value: "shared",
    subjectKind: "sui:object",
    provenance: "model"
  });
  const quiet = ownershipClaim(OBJ_A, "shared", { witness: "report-only", facet: `tool-declined:${OBJ_A}` });

  const result = compose([partial, modelled, quiet]);
  const reasonOf = (claim: Claim): string | undefined => result.excluded.find((e) => e.claimId === claim.claimId)?.reason;
  assert.ok(reasonOf(partial)?.startsWith("partial verifiability"), `got ${reasonOf(partial)}`);
  assert.ok(reasonOf(modelled)?.startsWith("provenance model"), `got ${reasonOf(modelled)}`);
  assert.equal(reasonOf(quiet), "witness-declared report-only by the emitter");

  // The reader must be able to tell "the tool declined" from "the protocol overruled the tool".
  const declared = (claim: Claim): string | undefined =>
    result.excluded.find((e) => e.claimId === claim.claimId)?.declaredWitness;
  assert.equal(declared(partial), "eligible", "the adapter asked for a witness; the protocol said no");
  assert.equal(declared(quiet), "report-only", "this one was the tool's own choice");
});

test("a conversion is downgraded on its mechanism, and the registry keeps conversions out of the algebra", () => {
  // `provenance: "imported"` used to be the rule's hook. It never fired: an importer preserves the
  // source's own provenance, so every converted claim arrived saying "deterministic". The structural
  // fact is the emitter, which an adapter sets and cannot inherit.
  const converted = sampleClaim("move.finding.signal", {
    subject: [DIGEST_LEAK],
    args: { network: "mainnet" },
    value: "SOME_FOREIGN_RULE",
    subjectKind: "sui:transaction",
    provenance: "deterministic",
    emitter: "imported",
    facet: "sarif:converted|tx"
  });
  assert.equal(converted.provenance, "deterministic", "conversion inherits the source's self-description");
  assert.equal(converted.witness, "report-only", "and is downgraded on the mechanism instead");

  const result = compose([converted]);
  assert.equal(result.carried.length, 1, "a converted signal is carried, never composed");
  assert.equal(result.corroborations.length, 0);

  // The load-bearing invariant: nothing that can collide may be spoken by a conversion. This is why the
  // provenance/emitter mix above was latent rather than live — and if a future predicate ever admits an
  // imported emitter while staying collidable, this check has to fail loudly.
  const collidableAndImported = PREDICATES.filter((def) => (def.collidable ?? true) && def.emitters.includes("imported"));
  assert.deepEqual(collidableAndImported.map((def) => def.id), [], "a conversion became able to witness a collidable fact");
});

test("an empty result cannot be written as if it were a clean one", () => {
  // This is Chase's own scar, re-cut: a hunt that ran zero passes once printed "Coverage: complete".
  // A claimset with no envelopes is the one document that satisfies every downstream check vacuously —
  // verify has no signatures to reject, compose has nothing to contradict — so the refusal belongs here.
  const clean = parseAnalysisReport(JSON.parse(readFileSync(join(root, "test/fixtures/clean-order.report.json"), "utf8")));
  const cleanTrace = parseTrace(JSON.parse(readFileSync(join(root, "test/fixtures/clean-order.trace.json"), "utf8")));
  const out = chaseToClaims({ trace: cleanTrace, report: clean, emittedAt: EMITTED_AT });

  assert.equal(out.claims.filter((c) => c.channel === "assert" && c.predicate !== "move.finding.signal").length > 0, true,
    "a trace still determines facts even when no detector fired — otherwise this proves nothing");

  const cli = resolve(root, "src/cli/index.ts");
  const reportPath = join(root, "test/fixtures/clean-order.report.json");
  const result = spawnSync("npx", ["tsx", cli, "emit", "chase", "--report", reportPath, "-o", "/tmp/maru-should-not-exist.json"], {
    encoding: "utf8",
    cwd: root,
    env: { ...process.env, MARU_KEYRING: "/tmp/maru-none.json" }
  });
  assert.equal(result.status, 1, `expected the empty emit to fail, got ${String(result.status)}: ${result.stderr.slice(0, 200)}`);
  assert.match(result.stderr, /EMPTY RESULT/);
  assert.ok(!existsSync("/tmp/maru-should-not-exist.json"), "refusing must not leave a file behind");

  // The bypass has to produce a real signed document, or "you can write it anyway" is a lie too.
  const scratch = join(root, ".tmp-test");
  commandRm(scratch);
  const ring = join(scratch, "ring.json");
  const gen = spawnSync("npx", ["tsx", cli, "key", "generate", "--tool", "chase", "--out", join(scratch, "keys"), "--keyring", ring], {
    encoding: "utf8", cwd: root, env: { ...process.env, MARU_KEYRING: ring }
  });
  assert.equal(gen.status, 0, gen.stderr.slice(0, 200));
  const allowed = spawnSync("npx", ["tsx", cli, "emit", "chase", "--report", reportPath, "--key", join(scratch, "keys", "chase.pem"), "--keyring", ring, "-o", join(scratch, "empty.json")], {
    encoding: "utf8",
    cwd: root,
    env: { ...process.env, MARU_ALLOW_EMPTY: "1" }
  });
  assert.equal(allowed.status, 0, "an operator who means it can still write the document");
  const written = JSON.parse(readFileSync(join(scratch, "empty.json"), "utf8")) as { envelopes: unknown[]; coverage: unknown[] };
  assert.equal(written.envelopes.length, 0, "empty means empty; the bypass must not invent a claim");
  assert.ok(Array.isArray(written.coverage) && written.coverage.length > 0, "and the document must carry why");
  commandRm(scratch);
});

// ------------------------------------------------------------------ summary

const failures = results.filter((r) => r.error !== null);
for (const r of results) {
  console.log(`${r.error === null ? "ok  " : "FAIL"} ${r.name}${r.error ? `\n     ${r.error}` : ""}`);
}
for (const line of skips) console.log(`SKIP ${line}`);
console.log(`\n${results.length - failures.length}/${results.length} passed${skips.length ? ` (${skips.length} control(s) not run)` : ""}`);
if (failures.length > 0) process.exit(1);
