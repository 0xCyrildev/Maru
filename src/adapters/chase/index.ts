import type { Claim } from "../../envelope/claim.js";
import type { CoverageRecord } from "../../envelope/coverage.js";
import { CHASE_TOOL } from "./methodology.js";
import { factsFromTrace } from "./from-trace.js";
import { claimsFromReport } from "./from-report.js";
import type { ChaseAnalysisReport, ChaseTrace } from "./wire.js";

export interface ChaseAdapterInput {
  trace?: ChaseTrace;
  report?: ChaseAnalysisReport;
  /** Only used when neither input carries one. Never guessed. */
  network?: string;
  emittedAt: string;
}

export interface ChaseAdapterOutput {
  claims: Claim[];
  coverage: CoverageRecord[];
  /** Evidence field names the adapter has no classification for — a gate failure, not a warning. */
  unclassified: string[];
  notes: string[];
}

/**
 * Chase 0.3.0 in, Maru claims out. Chase is not modified and is not a dependency: this reads the JSON
 * it already emits, plus the cached trace the report was built from.
 *
 * The split matters. A **trace** determines facts (what an object became, who owns it, what a resolved
 * signature returned, whether a module announced itself) and those are the only claims that can compose.
 * A **report** contributes signals and the premises those signals rest on. Give it only a report and it
 * says so — a signal-only input cannot corroborate anything, and pretending otherwise would let a label
 * stand in for a measurement.
 */
export function chaseToClaims(input: ChaseAdapterInput): ChaseAdapterOutput {
  const { trace, report } = input;
  if (!trace && !report) throw new Error("chaseToClaims needs a trace, a report, or both.");

  const networks = [trace?.network, report?.network, input.network].filter((n): n is string => Boolean(n));
  const digests = [trace?.digest, report?.digest].filter((d): d is string => Boolean(d));
  if (new Set(digests).size > 1) {
    throw new Error(`Refusing to adapt a trace for ${digests[0]} together with a report for ${digests[1]}.`);
  }
  const uniqueNetworks = [...new Set(networks)];
  if (uniqueNetworks.length > 1) throw new Error(`Refusing to adapt inputs that disagree about the network: ${uniqueNetworks.join(", ")}.`);
  if (uniqueNetworks.length === 0) {
    throw new Error("No network on the input. Maru does not default one: a claim about mainnet and a claim about testnet must never share a subject by accident.");
  }
  const network = uniqueNetworks[0] as string;
  if (!input.trace && !input.report) throw new Error("Nothing to adapt.");

  const claims: Claim[] = [];
  const coverage: CoverageRecord[] = [];
  const notes: string[] = [];
  let unclassified: string[] = [];

  if (trace) {
    const facts = factsFromTrace(trace, network, input.emittedAt);
    claims.push(...facts.claims);
    coverage.push(...facts.coverage);
  }

  if (report) {
    const fromReport = claimsFromReport(report, input.emittedAt);
    claims.push(...fromReport.claims);
    coverage.push(...fromReport.coverage);
    unclassified = fromReport.unclassified;
    if (!trace) {
      coverage.push({
        kind: "not-read",
        subject: report.digest,
        reason: "No trace was supplied, so no fact layer was derived. These claims are signals and premises only: they can be reported, but nothing here can corroborate or contradict another tool's fact.",
        toolId: CHASE_TOOL.id
      });
    }
    if (report.success === false) {
      notes.push("The transaction reverted. Findings here describe an attempt, not a completed effect.");
    }
  }

  return { claims, coverage, unclassified, notes };
}
