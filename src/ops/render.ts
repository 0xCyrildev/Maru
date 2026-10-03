import pc from "picocolors";
import type { Claim } from "../envelope/claim.js";
import type { CompositionResult } from "./compose.js";
import type { CoverageRecord } from "../envelope/coverage.js";

function id(value: string): string {
  return value.slice(0, 12);
}

export function renderClaims(claims: readonly Claim[]): string {
  const lines: string[] = [];
  for (const claim of [...claims].sort((a, b) => a.claimId.localeCompare(b.claimId))) {
    const flags = [
      claim.channel === "assume" ? pc.yellow("assume") : "assert",
      claim.witness === "eligible" ? pc.green("witness") : pc.gray("report-only"),
      claim.verifiability === "partial" ? pc.red(`partial(${claim.unverifiableFields.map((f) => f.reason).join("+")})`) : null,
      claim.provenance !== "deterministic" ? pc.magenta(claim.provenance) : null
    ].filter(Boolean);
    lines.push(`${id(claim.claimId)}  ${claim.methodology.tool}/${claim.predicate} = ${pc.bold(claim.value)}`);
    lines.push(`          ${claim.subjectUri}`);
    lines.push(`          ${flags.join(" ")}  facet ${id(claim.lineage.key)} (${claim.lineage.basis})`);
  }
  return lines.join("\n");
}

export function renderCoverage(coverage: readonly CoverageRecord[]): string {
  if (coverage.length === 0) return pc.gray("coverage: nothing was skipped, unread or incomplete");
  return [
    pc.bold(`coverage: ${coverage.length} record(s) — an absent finding here is an uncomputed finding`),
    ...coverage.map((c) => `  ${pc.red(c.kind)}  ${c.subject}\n          ${c.reason}`)
  ].join("\n");
}

export function renderComposition(result: CompositionResult): string {
  const out: string[] = [
    pc.bold("maru composition"),
    `engine ${result.engine.name}@${result.engine.version} · registry core@${result.registryMajor} · ${result.inputs.length} claim(s) in`,
    "",
    pc.yellow(result.headline),
    ""
  ];

  const section = (title: string, body: string[]): void => {
    if (body.length === 0) return;
    out.push(pc.bold(title), ...body, "");
  };

  section("CORROBORATE — independent opinions", result.corroborations.map((c) => {
    const opinions = c.opinions.map((o) => `      · ${o.tools.join(",")} via ${id(o.lineageKey)}${o.basis === "declared" ? pc.yellow(" [declared lineage]") : ""}`).join("\n");
    return `  ${c.topic}\n${opinions}`;
  }));

  section("OVERLAP — one construct, one opinion", result.overlaps.map((o) => `  ${o.topic}\n      ${o.claimIds.length} claim(s) on facet ${id(o.lineageKey)}: ${o.note}`));

  section("CONTRADICT — for a human, unresolved", result.contradictions.map((c) =>
    `  ${c.subjectUri}\n      ${c.left.tool}/${c.left.predicate}=${c.left.value}  vs  ${c.right.tool}/${c.right.predicate}=${c.right.value}\n      ${c.nextAction}: ${c.note}`
  ));

  section("SUPPRESSED — a dispute blocks escalation", result.suppressedCorroborations.map((s) => `  ${s.topic}\n      ${s.claimIds.map(id).join(", ")}: ${s.reason}`));

  section("SILENT — an assumption falsified by a determination", result.silences.map((s) =>
    `  ${s.subjectUri}\n      ${s.assumption.tool} assumed ${s.assumption.value}; ${s.assertion.tool} determined ${s.assertion.value}\n      ${s.note}`
  ));

  section("DISCHARGED — an assumption confirmed", result.discharged.map((d) => `  ${d.subjectUri}: ${d.assumption.tool} assumed ${d.assumption.value}, ${d.assertion.tool} determined the same`));

  section("UNDISCHARGED — nobody checked", result.undischarged.map((u) => `  ${u.assumption.tool}/${u.assumption.predicate}=${u.assumption.value} on ${u.subjectUri}\n      ${u.reason}`));

  section("EXCLUDED — reported, never a witness", result.excluded.map((e) => `  ${id(e.claimId)} ${e.predicate}: ${e.reason}`));

  section("CARRIED — outside the algebra", result.carried.map((c) => `  ${id(c.claimId)} ${c.predicate} = ${c.value}`));

  section("NOTHING TO SAY — one opinion, no second", result.solitary.map((s) => `  ${s.topic}  (${s.claimIds.length} claim(s))`));

  out.push(renderCoverage(result.coverage));
  return out.join("\n");
}
