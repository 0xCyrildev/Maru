import type { Claim, Provenance } from "../envelope/claim.js";
import { groupForPredicate } from "../registry/core.js";
import { provenancesOf } from "./refuse.js";

/**
 * A topic is "the same thing two tools could be talking about": one conflict space (a predicate, or a
 * declared cross-predicate group) plus one subject. Lineage is a separate question answered somewhere
 * else — a topic can hold two opinions or one opinion written twice.
 */
export function topicOf(claim: Claim): string {
  const group = groupForPredicate(claim.predicate);
  return `${group?.id ?? claim.predicate}|${claim.subjectUri}`;
}

export interface Opinion {
  lineageKey: string;
  facet: string;
  basis: "derived" | "declared";
  claimIds: string[];
  tools: string[];
  provenances: Provenance[];
}

export interface TopicGroup {
  topic: string;
  space: string;
  subjectUri: string;
  opinions: Opinion[];
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

/**
 * Groups witness-eligible assertions by topic, then collapses each topic to one opinion per distinct
 * lineage key. This is the rule inherited from Chase's corroboration: volume from one detector is one
 * opinion, so the *list* of opinions is the output and there is no number to escalate with.
 */
export function buildTopics(assertions: readonly Claim[]): TopicGroup[] {
  const byTopic = new Map<string, Claim[]>();
  for (const claim of assertions) {
    const topic = topicOf(claim);
    const bucket = byTopic.get(topic);
    if (bucket) bucket.push(claim);
    else byTopic.set(topic, [claim]);
  }

  const groups: TopicGroup[] = [];
  for (const [topic, claims] of byTopic) {
    const byLineage = new Map<string, Claim[]>();
    for (const claim of claims) {
      const bucket = byLineage.get(claim.lineage.key);
      if (bucket) bucket.push(claim);
      else byLineage.set(claim.lineage.key, [claim]);
    }
    const opinions: Opinion[] = [...byLineage.entries()]
      .map(([lineageKey, list]) => ({
        lineageKey,
        facet: list[0]?.lineage.facet ?? "",
        basis: list[0]?.lineage.basis ?? "declared",
        claimIds: sortedUnique(list.map((c) => c.claimId)),
        tools: sortedUnique(list.map((c) => c.methodology.tool)),
        provenances: provenancesOf(list)
      }))
      .sort((a, b) => a.lineageKey.localeCompare(b.lineageKey));

    groups.push({
      topic,
      space: topic.split("|")[0] ?? topic,
      subjectUri: claims[0]?.subjectUri ?? "",
      opinions
    });
  }
  return groups.sort((a, b) => a.topic.localeCompare(b.topic));
}

export interface Corroboration {
  relation: "corroborate";
  topic: string;
  subjectUri: string;
  /** One entry per independent opinion. Two entries means two mechanisms, never two rows. */
  opinions: Opinion[];
  /** Which opinions carry a declared rather than derived lineage — declared lineage is weaker and is shown, not hidden. */
  declaredLineage: string[];
}

export interface Overlap {
  relation: "overlap";
  topic: string;
  subjectUri: string;
  lineageKey: string;
  facet: string;
  claimIds: string[];
  note: string;
}

export interface JoinResult {
  corroborations: Corroboration[];
  overlaps: Overlap[];
  /** Topics with exactly one opinion: seen, compared, and nothing to say. Not agreement — absence of a second opinion. */
  solitary: { topic: string; subjectUri: string; claimIds: string[] }[];
}

export function join(assertions: readonly Claim[]): JoinResult {
  const corroborations: Corroboration[] = [];
  const overlaps: Overlap[] = [];
  const solitary: { topic: string; subjectUri: string; claimIds: string[] }[] = [];

  for (const group of buildTopics(assertions)) {
    if (group.opinions.length >= 2) {
      corroborations.push({
        relation: "corroborate",
        topic: group.topic,
        subjectUri: group.subjectUri,
        opinions: group.opinions,
        declaredLineage: group.opinions.filter((o) => o.basis === "declared").map((o) => o.lineageKey)
      });
    } else {
      const opinion = group.opinions[0];
      if (!opinion) continue;
      if (opinion.claimIds.length >= 2) {
        overlaps.push({
          relation: "overlap",
          topic: group.topic,
          subjectUri: group.subjectUri,
          lineageKey: opinion.lineageKey,
          facet: opinion.facet,
          claimIds: opinion.claimIds,
          note: "Same lineage: these rows describe one construct and count as one opinion."
        });
      } else {
        solitary.push({ topic: group.topic, subjectUri: group.subjectUri, claimIds: opinion.claimIds });
      }
    }
  }

  return { corroborations, overlaps, solitary };
}
