import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export interface MoveParameter {
  name: string;
  type: string;
}

export interface MoveFunction {
  name: string;
  module: string;
  /** The module's declared address name, as written (`chase_test`), not a resolved id. */
  addressName: string;
  visibility: "public" | "public(package)" | "public(friend)" | "entry" | "private";
  typeParameters: string[];
  params: MoveParameter[];
  /** The declared return type as written, or null for a unit return. */
  returns: string | null;
  body: string;
  file: string;
}

export interface MoveModule {
  addressName: string;
  name: string;
  structs: string[];
  functions: MoveFunction[];
  emitsEvent: boolean;
  file: string;
}

const PRIMITIVES = new Set(["u8", "u16", "u32", "u64", "u128", "u256", "bool", "address", "signer", "TxContext"]);

function splitTopLevel(text: string, separator: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "<" || ch === "(" || ch === "[") depth += 1;
    else if (ch === ">" || ch === ")" || ch === "]") depth -= 1;
    if (ch === separator && depth === 0) {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim().length > 0) out.push(current);
  return out;
}

/** Brace-matched body, because a regex over nested blocks is how a parser quietly starts lying. */
function readBlock(source: string, openIndex: number): string {
  let depth = 0;
  for (let i = openIndex; i < source.length; i += 1) {
    const ch = source[i];
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(openIndex + 1, i);
    }
  }
  return source.slice(openIndex + 1);
}

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function classifyVisibility(header: string): MoveFunction["visibility"] {
  if (/public\(friend\)/.test(header)) return "public(friend)";
  if (/public\(package\)/.test(header)) return "public(package)";
  if (/\bentry\b/.test(header)) return "entry";
  if (/\bpublic\b/.test(header)) return "public";
  return "private";
}

/**
 * Regex over Move source, not the Move compiler — the same tradeoff sui-invariant-fuzzer documents for
 * itself. It reads module headers, struct names, function signatures and bodies. It does **not**
 * resolve imports, aliases, constants, or control flow, and every claim it produces says so in its
 * limits. A parser that cannot see an indirect path must not emit a claim that implies it looked.
 */
export function parseMoveDirectory(dir: string): MoveModule[] {
  const modules: MoveModule[] = [];

  for (const file of readdirSync(dir).filter((f) => f.endsWith(".move")).sort()) {
    const raw = readFileSync(join(dir, file), "utf8");
    const text = stripComments(raw);
    const header = /module\s+([A-Za-z0-9_]+)::([A-Za-z0-9_]+)\s*(?:{|;)/.exec(text);
    const addressName = header?.[1] ?? "";
    const moduleName = header?.[2] ?? "";
    if (!addressName || !moduleName) continue;

    const structs = [...text.matchAll(/\bstruct\s+([A-Za-z0-9_]+)/g)].map((m) => m[1]).filter((s): s is string => Boolean(s));
    const functions: MoveFunction[] = [];

    const signature = /((?:public(?:\((?:friend|package)\))?\s+|entry\s+|native\s+)*)fun\s+([A-Za-z0-9_]+)\s*(<[^>]*>)?\s*\(/g;
    for (const match of [...text.matchAll(signature)]) {
      const whole = match[0];
      const name = match[2];
      if (!name) continue;
      const typeParameterText = match[3] ?? "";
      const openParen = (match.index ?? 0) + whole.length - 1;
      const params = readParenthesized(text, openParen);
      // readParenthesized's raw excludes the closing ")=", so the first byte after the parameter list
      // sits at openParen + raw.length + 1. Getting this off by one drops every declared return type,
      // which the parser then reports as a unit return — a silent wrong answer rather than an error.
      const afterParams = text.slice(openParen + params.raw.length + 1);
      const returnMatch = /^\s*:\s*([^{;]+?)\s*\{/.exec(afterParams) ?? /^\s*:\s*([^{;]+?)\s*;/.exec(afterParams);
      const returns = returnMatch?.[1]?.trim().replace(/\s+/g, " ") ?? null;
      const bodyOpen = text.indexOf("{", openParen + params.raw.length + 1);
      const body = bodyOpen >= 0 && /{/.test(afterParams) ? readBlock(text, bodyOpen) : "";

      functions.push({
        name,
        module: moduleName,
        addressName,
        visibility: classifyVisibility(whole),
        typeParameters: splitTopLevel(typeParameterText.replace(/^<|>$/g, ""), ",").map((t) => t.trim()).filter(Boolean),
        params: params.items.map(parseParam).filter((p): p is MoveParameter => p !== null),
        returns,
        body,
        file
      });
    }

    modules.push({
      addressName,
      name: moduleName,
      structs: [...new Set(structs)].sort(),
      functions,
      emitsEvent: /event::emit\s*[<(]/.test(text),
      file
    });
  }

  return modules;
}

function readParenthesized(text: string, openIndex: number): { raw: string; items: string[] } {
  let depth = 0;
  let raw = "";
  for (let i = openIndex; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "(") depth += 1;
    if (ch === ")") {
      depth -= 1;
      if (depth === 0) break;
    }
    raw += ch;
  }
  const inner = raw.startsWith("(") ? raw.slice(1) : raw;
  return { raw, items: splitTopLevel(inner, ",") };
}

function parseParam(entry: string): MoveParameter | null {
  const text = entry.trim();
  const colon = text.indexOf(":");
  if (colon === -1) return null;
  const name = text.slice(0, colon).trim();
  const type = text.slice(colon + 1).trim().replace(/\s+/g, " ");
  if (!name || !type) return null;
  return { name, type };
}

export function isMutableReference(type: string): boolean {
  return /^&mut\s/.test(type);
}

export function isImmutableReference(type: string): boolean {
  return /^&\s*[A-Za-z0-9_$]/.test(type) && !/^&mut\s/.test(type);
}

export function isTxContext(type: string): boolean {
  return /(^|[<&\s])TxContext(\s*>|\s|$)/.test(type);
}

export function isPrimitive(type: string): boolean {
  const bare = type.replace(/^&mut\s+/, "").replace(/^&/, "").trim();
  return PRIMITIVES.has(bare) || /^[A-Z]$/.test(bare);
}

export function baseType(type: string): string {
  return type.replace(/^&mut\s+/, "").replace(/^&\s*/, "").split("<")[0]?.trim() ?? type;
}
