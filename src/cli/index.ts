#!/usr/bin/env node
import crypto from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Command } from "commander";
import pc from "picocolors";

import { MaruError } from "../lib/errors.js";
import { keyIdForJwk, publicKeyOf } from "../dsse/keys.js";
import { loadKeyring, saveKeyring, toolsIn, withEntry, withoutKey, type Keyring, type KeyringEntry } from "../dsse/keyring.js";
import { signStatement, type DsseEnvelope } from "../dsse/sign.js";
import { toStatement } from "../envelope/statement.js";
import { compositionStatement } from "../ops/compose.js";
import { makeClaimset, verifyAll } from "../envelope/claimset.js";
import type { VerifiedClaim } from "../dsse/verify.js";
import type { Claim } from "../envelope/claim.js";
import type { CoverageRecord } from "../envelope/coverage.js";
import { parseAnalysisReport, parseTrace } from "../adapters/chase/wire.js";
import { chaseToClaims } from "../adapters/chase/index.js";
import { claimsFromSource } from "../emitters/move-static/index.js";
import { compose, ENGINE } from "../ops/compose.js";
import { renderClaims, renderComposition, renderCoverage } from "../ops/render.js";
import { exportSarif, importSarif } from "../adapters/sarif/index.js";
import { CONFLICT_GROUPS, PREDICATES, registryVersion } from "../registry/core.js";

/**
 * Trust model in one file: a claim is only as good as the pinned key that signed it, and a key is only
 * as good as the human who pasted it into a ring they read. There is no PKI here, and no attempt to
 * pretend there should be — which is why signing is refused rather than skipped when a key is unpinned.
 */
function defaultKeyringPath(): string {
  return process.env.MARU_KEYRING ?? join(homedir(), ".maru", "keyring.json");
}

function readJson(path: string): unknown {
  if (path === "-") return JSON.parse(readFileSync(0, "utf8"));
  if (!existsSync(path)) throw new MaruError("INPUT_MISSING", `No such file: ${path}`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeOut(path: string | undefined, text: string): void {
  if (!path || path === "-") {
    process.stdout.write(`${text}\n`);
    return;
  }
  const target = resolve(path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, text.endsWith("\n") ? text : `${text}\n`, "utf8");
}

function loadSigner(pemPath: string, ring: Keyring): { privateKey: crypto.KeyObject; keyId: string; toolId: string } {
  const privateKey = crypto.createPrivateKey(readFileSync(pemPath, "utf8"));
  const jwk = publicKeyOf(privateKey);
  const keyId = keyIdForJwk(jwk);
  const entry = ring.entries.find((e) => e.keyId === keyId);
  if (!entry) {
    throw new MaruError(
      "UNREGISTERED_KEY",
      `The key pair in ${pemPath} hashes to ${keyId}, which is not in ${defaultKeyringPath()}. Signing anyway would produce envelopes nobody can attribute, so it is refused: pin the public half with \`maru key add\` first.`
    );
  }
  return { privateKey, keyId, toolId: entry.toolId };
}

function signClaims(claims: readonly Claim[], pemPath: string | undefined, ringPath: string): DsseEnvelope[] {
  if (!pemPath) return [];
  const ring = loadKeyring(ringPath);
  const signer = loadSigner(resolve(pemPath), ring);
  const mismatched = claims.find((c) => c.methodology.tool !== signer.toolId);
  if (mismatched) {
    throw new MaruError(
      "TOOL_KEY_MISMATCH",
      `Refusing to sign a "${mismatched.methodology.tool}" claim with a key pinned to "${signer.toolId}". A borrowed label is the exact failure the keyring exists to prevent.`
    );
  }
  return claims.map((claim) => signStatement(toStatement(claim), signer));
}

function collect(
  claims: readonly Claim[],
  coverage: readonly CoverageRecord[],
  options: { key?: string; keyring: string; out: string },
  label: string
): void {
  if (claims.length === 0 && process.env.MARU_ALLOW_EMPTY !== "1") {
    // An empty claimset is the one document that reads as success everywhere downstream: it verifies with
    // no signatures to check and composes to an empty report. Chase learned this the hard way, when a hunt
    // that ran zero passes printed "Coverage: complete". Refuse the write; print the coverage instead.
    console.error(`${pc.red("EMPTY RESULT")} ${label} emitted no claims. Nothing was written — an empty claimset would verify vacuously and compose to silence, which reads exactly like a clean target.`);
    console.error(renderCoverage(coverage));
    console.error(pc.gray("If this run genuinely produced nothing to say, re-run with MARU_ALLOW_EMPTY=1 to write the document anyway, with its coverage records."));
    process.exitCode = 1;
    return;
  }
  if (!options.key) {
    console.log(renderClaims(claims));
    console.log(renderCoverage(coverage));
    console.error(pc.yellow("unsigned preview only — no file was written. An unsigned document must not look like an interchange format."));
    return;
  }
  const envelopes = signClaims(claims, options.key, options.keyring);
  writeOut(options.out, JSON.stringify(makeClaimset(envelopes, [...coverage]), null, 2));
  console.error(pc.green(`${envelopes.length} claim(s) signed to ${options.out}`));
}

function parseAddresses(values: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const value of values) {
    const eq = value.indexOf("=");
    if (eq <= 0) throw new MaruError("BAD_ARGUMENT", `--address expects name=0x…, got "${value}".`);
    out[value.slice(0, eq)] = value.slice(eq + 1);
  }
  return out;
}

function verifyInputs(files: string[], ringPath: string): { verified: VerifiedClaim[]; coverage: CoverageRecord[]; failures: { source: string; error: string }[] } {
  return verifyAll(files.map((f) => ({ doc: readJson(f), source: f })), loadKeyring(ringPath));
}

function reportFailures(failures: { source: string; error: string }[]): void {
  for (const failure of failures) console.error(`${pc.red("REFUSED")} ${failure.source}: ${failure.error}`);
}

const program = new Command();
program
  .name("maru")
  .description("Signed claim interchange and composition algebra for Web3 security tooling")
  .version(ENGINE.version);

const key = program.command("key").description("Pinned trust: a keyring you read, not a PKI");

key
  .command("generate")
  .requiredOption("--tool <id>", "tool id this key will sign for")
  .option("--out <dir>", "where to write the private key PEM", join(homedir(), ".maru", "keys"))
  .option("--keyring <path>", "keyring to update", defaultKeyringPath())
  .action((options: { tool: string; out: string; keyring: string }) => {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = publicKeyOf(privateKey);
    const keyId = keyIdForJwk(jwk);
    mkdirSync(resolve(options.out), { recursive: true });
    const pemPath = join(resolve(options.out), `${options.tool}.pem`);
    if (existsSync(pemPath)) throw new MaruError("KEY_EXISTS", `${pemPath} already holds a key. Refusing to overwrite a signing key.`);
    writeFileSync(pemPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const entry: KeyringEntry = { toolId: options.tool, keyId, jwk, addedAt: new Date().toISOString(), note: `generated locally at ${pemPath}` };
    saveKeyring(withEntry(loadKeyring(options.keyring), entry), options.keyring);
    console.log(
      `${pc.green("key generated")}\n  tool   ${options.tool}\n  keyid  ${keyId}\n  secret ${pemPath} (0600 — this file is the only thing that makes your claims yours)\n  ring   ${options.keyring}`
    );
  });

key
  .command("add")
  .argument("<jwk.json>", "a JWK public key, or - for stdin")
  .requiredOption("--tool <id>", "tool id this key belongs to")
  .option("--note <text>", "why you pinned it", "")
  .option("--keyring <path>", "keyring to update", defaultKeyringPath())
  .action((file: string, options: { tool: string; note: string; keyring: string }) => {
    const jwk = JSON.parse(String(readJson(file)));
    const entry: KeyringEntry = { toolId: options.tool, keyId: keyIdForJwk(jwk), jwk, addedAt: new Date().toISOString(), note: options.note };
    saveKeyring(withEntry(loadKeyring(options.keyring), entry), options.keyring);
    console.log(`${pc.green("pinned")} ${entry.keyId} → ${entry.toolId} in ${options.keyring}`);
  });

key
  .command("list")
  .option("--keyring <path>", "keyring to read", defaultKeyringPath())
  .action((options: { keyring: string }) => {
    const ring = loadKeyring(options.keyring);
    if (ring.entries.length === 0) {
      console.log(`${options.keyring} holds no keys, so nothing in it can be attributed — and nothing unattributed is trusted.`);
      return;
    }
    console.log(`tools: ${toolsIn(ring).join(", ")}\n`);
    for (const entry of ring.entries) console.log(`${entry.keyId}  ${entry.toolId}  added ${entry.addedAt}${entry.note ? `  (${entry.note})` : ""}`);
  });

key
  .command("drop")
  .argument("<keyid>")
  .option("--keyring <path>", "keyring to edit", defaultKeyringPath())
  .action((keyId: string, options: { keyring: string }) => {
    const { ring, dropped } = withoutKey(loadKeyring(options.keyring), keyId);
    if (!dropped) {
      console.log(`${keyId} was not in the ring.`);
      return;
    }
    saveKeyring(ring, options.keyring);
    console.log(`${pc.yellow("dropped")} ${keyId} (${dropped.toolId}). v0 has no revocation list, so every claim it ever signed still verifies. Re-check what you relied on.`);
  });

const emit = program.command("emit").description("Turn a tool's own output into signed claims");

emit
  .command("chase")
  .requiredOption("--report <file>", "`chase analyze --json` output")
  .option("--trace <file>", "the normalized trace, which is what carries determined facts")
  .option("--network <name>", "only used if neither input states one")
  .option("--key <pem>", "private key to sign with; must already be pinned")
  .option("--keyring <path>", "keyring the signing key is checked against", defaultKeyringPath())
  .option("-o, --out <file>", "claimset to write", "-")
  .action((options: { report: string; trace?: string; network?: string; key?: string; keyring: string; out: string }) => {
    const report = parseAnalysisReport(readJson(options.report));
    const trace = options.trace ? parseTrace(readJson(options.trace)) : undefined;
    const out = chaseToClaims({
      ...(trace ? { trace } : {}),
      report,
      ...(options.network ? { network: options.network } : {}),
      emittedAt: new Date().toISOString()
    });
    if (out.unclassified.length > 0) {
      throw new MaruError("UNCLASSIFIED_EVIDENCE", `Chase emitted evidence fields this adapter has no rule for: ${out.unclassified.join(", ")}. Classify them in src/adapters/chase/from-report.ts; a silently dropped field is a claim about having seen everything.`);
    }
    for (const note of out.notes) console.error(pc.gray(`note  ${note}`));
    collect(out.claims, out.coverage, options, "chase");
  });

emit
  .command("move-static")
  .requiredOption("--sources <dir>", "directory of .move sources")
  .requiredOption("--network <name>", "network the package was published to")
  .option("--address <name=id>", "resolve a named address to a published package id (repeatable)", (v: string, prev: string[]) => [...prev, v], [] as string[])
  .option("--digest <tx>", "answer this transaction's event-presence question (an assumption, never an assertion)")
  .option("--key <pem>", "private key to sign with; must already be pinned")
  .option("--keyring <path>", "keyring the signing key is checked against", defaultKeyringPath())
  .option("-o, --out <file>", "claimset to write", "-")
  .action((options: { sources: string; network: string; address: string[]; digest?: string; key?: string; keyring: string; out: string }) => {
    const packageAddresses = parseAddresses(options.address);
    if (Object.keys(packageAddresses).length === 0) {
      throw new MaruError("BAD_ARGUMENT", "No --address name=0x… given. A source reader that guesses a package id invents a subject no other tool can match.");
    }
    const result = claimsFromSource({
      sourceDir: resolve(options.sources),
      network: options.network,
      packageAddresses,
      emittedAt: new Date().toISOString(),
      ...(options.digest ? { digest: options.digest } : {})
    });
    for (const note of result.notes) console.error(pc.gray(`note  ${note}`));
    collect(result.claims, [], options, "move-static");
  });

program
  .command("verify")
  .argument("<files...>", "claimsets or DSSE envelopes")
  .option("--keyring <path>", "pinned keys", defaultKeyringPath())
  .description("Check signature, attribution and claim identity — never whether a claim is true")
  .action((files: string[], options: { keyring: string }) => {
    const { verified, coverage, failures } = verifyInputs(files, options.keyring);
    if (verified.length > 0) {
      console.log(renderClaims(verified.map((v) => v.claim)));
      console.log(pc.green(`\n${verified.length} claim(s) verified`) + ` against ${toolsIn(loadKeyring(options.keyring)).length} pinned key(s)`);
      console.log(renderCoverage(coverage));
      console.log(pc.gray("verified means attributable and internally consistent. It does not mean correct."));
    }
    reportFailures(failures);
    if (failures.length > 0 || verified.length === 0) {
      // Zero verified and zero failures means the inputs carried no claims at all. That is not a pass.
      process.exitCode = 1;
      if (failures.length === 0) console.error(pc.red("nothing to verify: the input documents held no envelopes."));
    }
  });

program
  .command("compose")
  .argument("<files...>", "claimsets and envelopes from any number of tools")
  .option("--keyring <path>", "pinned keys", defaultKeyringPath())
  .option("-o, --out <file>", "composition result JSON")
  .option("--key <pem>", "sign the composition result")
  .description("Apply the composition rules: corroborate, overlap, contradict, silent")
  .action((files: string[], options: { keyring: string; out?: string; key?: string }) => {
    const { verified, coverage, failures } = verifyInputs(files, options.keyring);
    reportFailures(failures);
    if (verified.length === 0) {
      console.error(pc.red("nothing verified, so nothing composed. A composition over unverified claims is unsigned opinion wearing a JSON shape."));
      process.exitCode = 1;
      return;
    }
    const result = compose(verified.map((v) => v.claim), coverage);
    console.log(renderComposition(result));
    if (options.key) {
      const signer = loadSigner(resolve(options.key), loadKeyring(options.keyring));
      const envelope = signStatement(compositionStatement(result), signer);
      writeOut(options.out, JSON.stringify(makeClaimset([envelope], result.coverage), null, 2));
    } else {
      writeOut(options.out, JSON.stringify(result, null, 2));
    }
    if (failures.length > 0) process.exitCode = 1;
  });

program
  .command("registry")
  .option("--json", "machine-readable")
  .description("Print the closed predicate registry: what may be assumed, determined, and collided")
  .action((options: { json?: boolean }) => {
    if (options.json) {
      writeOut(undefined, JSON.stringify({ registry: registryVersion(), predicates: PREDICATES, conflictGroups: CONFLICT_GROUPS }, null, 2));
      return;
    }
    console.log(`${pc.bold(`registry ${registryVersion()}`)} — ${PREDICATES.length} predicates, closed. What is not here cannot be assumed, determined or collided, and a missing predicate is reported as incomparability rather than agreement.\n`);
    for (const def of PREDICATES) {
      console.log(`${pc.bold(def.id)}  ${def.subjectKind}  [${def.values ? def.values.join("|") : "(open)"}]`);
      console.log(`      args ${def.args.map((a) => `${a.name}:${a.encoder}`).join(", ") || "(none)"} · emitters ${def.emitters.join(",")}${def.assertEmitters ? ` · asserters ${def.assertEmitters.join(",")}` : ""}${def.collidable === false ? " · outside the algebra" : ""}`);
      console.log(pc.gray(`      ${def.meaning}`));
    }
    console.log("");
    for (const group of CONFLICT_GROUPS) {
      console.log(`${pc.bold(`conflict group ${group.id}`)}: ${group.predicates.join(" ↔ ")} over [${group.domain.join("|")}]`);
      console.log(pc.gray("      curated by hand. A typo here is fabricated agreement or a missed contradiction, which is why the conformance gate reads it."));
    }
  });

const sarif = program.command("sarif").description("SARIF 2.1.0 interchange — conversion is not composition");

sarif
  .command("export")
  .argument("<claimset>")
  .option("--keyring <path>", "pinned keys", defaultKeyringPath())
  .option("-o, --out <file>", "SARIF log to write", "-")
  .action((file: string, options: { keyring: string; out: string }) => {
    const { verified, coverage, failures } = verifyInputs([file], options.keyring);
    reportFailures(failures);
    writeOut(options.out, JSON.stringify(exportSarif(verified.map((v) => v.claim), coverage), null, 2));
  });

sarif
  .command("import")
  .argument("<sarif>")
  .option("-o, --out <file>", "import report to write", "-")
  .action((file: string, options: { out: string }) => {
    const result = importSarif(readJson(file));
    writeOut(options.out, JSON.stringify({ maru: "maru/import/v1", claims: result.claims, refused: result.refused }, null, 2));
    for (const refusal of result.refused) console.error(`${pc.yellow("NOT COMPOSABLE")} ${refusal.ruleId}: ${refusal.reason}`);
    console.error(`${result.claims.length} claim(s) round-tripped; ${result.refused.length} result(s) convertible but outside the algebra.`);
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  if (error instanceof MaruError) {
    console.error(`${pc.red(error.code)}  ${error.message}`);
  } else {
    console.error(pc.red(String(error instanceof Error ? error.stack ?? error.message : error)));
  }
  process.exit(1);
});
