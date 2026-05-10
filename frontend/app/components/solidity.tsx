"use client";

import { Fragment, type ReactNode } from "react";

// Lightweight Solidity tokenizer — good enough for read-only display, no deps.
// Produces a flat sequence of {kind, text} chunks per line.

type TokenKind =
  | "comment"
  | "string"
  | "keyword"
  | "type"
  | "literal"
  | "punct"
  | "ident"
  | "ws";

const KEYWORDS = new Set([
  "contract", "library", "interface", "abstract", "is", "using",
  "function", "modifier", "constructor", "fallback", "receive",
  "returns", "return", "public", "private", "internal", "external",
  "view", "pure", "payable", "memory", "storage", "calldata",
  "struct", "enum", "mapping", "event", "emit", "anonymous", "indexed",
  "require", "assert", "revert", "if", "else", "for", "while", "do",
  "break", "continue", "new", "delete", "try", "catch", "throw",
  "this", "super", "msg", "tx", "block", "now", "gasleft",
  "virtual", "override", "immutable", "constant",
  "pragma", "solidity", "import", "from", "as",
  "abi", "selfdestruct", "suicide",
  "true", "false", "null",
]);

const TYPE_RE = /^(?:address|bool|string|bytes(?:[1-9]|[12][0-9]|3[0-2])?|u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|fixed|ufixed|var)$/;

const TOKEN_COLOR: Record<TokenKind, string> = {
  comment: "text-fg-muted italic",
  string: "text-emerald-300/90",
  keyword: "text-blue-300/90",
  type: "text-violet-300/90",
  literal: "text-amber-300/90",
  punct: "text-fg-tertiary",
  ident: "text-fg-primary",
  ws: "",
};

interface Token {
  kind: TokenKind;
  text: string;
}

export function tokenizeSolidityLine(line: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  const n = line.length;
  while (i < n) {
    const c = line[i];

    // Line comment
    if (c === "/" && line[i + 1] === "/") {
      out.push({ kind: "comment", text: line.slice(i) });
      i = n;
      continue;
    }
    // Block comment (single-line slice; we're rendering line-by-line)
    if (c === "/" && line[i + 1] === "*") {
      const end = line.indexOf("*/", i + 2);
      const stop = end >= 0 ? end + 2 : n;
      out.push({ kind: "comment", text: line.slice(i, stop) });
      i = stop;
      continue;
    }
    // String
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      while (j < n && line[j] !== quote) {
        if (line[j] === "\\") j += 2;
        else j += 1;
      }
      const stop = Math.min(j + 1, n);
      out.push({ kind: "string", text: line.slice(i, stop) });
      i = stop;
      continue;
    }
    // Number / hex
    if (/[0-9]/.test(c)) {
      const m = line.slice(i).match(/^(?:0x[0-9a-fA-F_]+|[0-9_]+(?:\.[0-9_]+)?(?:e[+-]?[0-9]+)?)/);
      if (m) {
        out.push({ kind: "literal", text: m[0] });
        i += m[0].length;
        continue;
      }
    }
    // Identifier / keyword / type
    if (/[A-Za-z_$]/.test(c)) {
      const m = line.slice(i).match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
      if (m) {
        const word = m[0];
        let kind: TokenKind = "ident";
        if (KEYWORDS.has(word)) kind = "keyword";
        else if (TYPE_RE.test(word)) kind = "type";
        out.push({ kind, text: word });
        i += word.length;
        continue;
      }
    }
    // Whitespace
    if (/\s/.test(c)) {
      const m = line.slice(i).match(/^\s+/);
      if (m) {
        out.push({ kind: "ws", text: m[0] });
        i += m[0].length;
        continue;
      }
    }
    // Punctuation / operator
    out.push({ kind: "punct", text: c });
    i += 1;
  }
  return out;
}

export function HighlightedLine({ line }: { line: string }) {
  const tokens = tokenizeSolidityLine(line);
  return (
    <>
      {tokens.map((t, i) => (
        <Fragment key={i}>
          {t.kind === "ws" ? (
            t.text
          ) : (
            <span className={TOKEN_COLOR[t.kind]}>{t.text}</span>
          )}
        </Fragment>
      ))}
    </>
  );
}

// ──────────────────────────────────────────────────────────────────────────
// LCS-based line diff
// ──────────────────────────────────────────────────────────────────────────

export type DiffRow =
  | { kind: "equal"; left: string; right: string; lLine: number; rLine: number }
  | { kind: "del"; left: string; lLine: number }
  | { kind: "add"; right: string; rLine: number };

export function diffLines(a: string, b: string): DiffRow[] {
  const aLines = a.split("\n");
  const bLines = b.split("\n");
  const m = aLines.length;
  const n = bLines.length;

  // LCS table
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      if (aLines[i] === bLines[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
      else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const rows: DiffRow[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (aLines[i] === bLines[j]) {
      rows.push({ kind: "equal", left: aLines[i], right: bLines[j], lLine: i + 1, rLine: j + 1 });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      rows.push({ kind: "del", left: aLines[i], lLine: i + 1 });
      i++;
    } else {
      rows.push({ kind: "add", right: bLines[j], rLine: j + 1 });
      j++;
    }
  }
  while (i < m) {
    rows.push({ kind: "del", left: aLines[i], lLine: i + 1 });
    i++;
  }
  while (j < n) {
    rows.push({ kind: "add", right: bLines[j], rLine: j + 1 });
    j++;
  }
  return rows;
}

// Render a side-by-side diff: empty cells where the row is one-sided.
export function SideBySideDiff({ left, right }: { left: string; right: string }) {
  const rows = diffLines(left, right);
  return (
    <div className="overflow-auto max-h-[560px] border border-border rounded-lg bg-surface">
      <table className="w-full text-[11.5px] leading-relaxed font-mono">
        <thead>
          <tr className="bg-surface-2">
            <th
              colSpan={2}
              className="text-left px-3 py-1.5 border-b border-border text-2xs uppercase tracking-wider text-sev-high font-medium"
            >
              vulnerable.sol
            </th>
            <th
              colSpan={2}
              className="text-left px-3 py-1.5 border-b border-border border-l border-border text-2xs uppercase tracking-wider text-sev-opt font-medium"
            >
              patched.sol
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, idx) => {
            const leftBg =
              r.kind === "del"
                ? "bg-sev-high-bg"
                : r.kind === "add"
                  ? "bg-surface-2/40"
                  : "";
            const rightBg =
              r.kind === "add"
                ? "bg-sev-opt-bg"
                : r.kind === "del"
                  ? "bg-surface-2/40"
                  : "";
            const leftMark = r.kind === "del" ? "-" : " ";
            const rightMark = r.kind === "add" ? "+" : " ";
            return (
              <tr key={idx}>
                <td
                  className={`text-fg-muted text-right pr-2 pl-3 select-none w-10 ${leftBg}`}
                >
                  {r.kind === "del" || r.kind === "equal" ? r.lLine : ""}
                </td>
                <td className={`whitespace-pre pr-3 ${leftBg}`}>
                  <span
                    className={`inline-block w-3 select-none ${
                      r.kind === "del" ? "text-sev-high" : "text-fg-muted"
                    }`}
                  >
                    {leftMark}
                  </span>
                  {r.kind === "del" ? (
                    <HighlightedLine line={r.left} />
                  ) : r.kind === "equal" ? (
                    <HighlightedLine line={r.left} />
                  ) : (
                    " "
                  )}
                </td>
                <td
                  className={`text-fg-muted text-right pr-2 pl-3 select-none w-10 border-l border-border ${rightBg}`}
                >
                  {r.kind === "add" || r.kind === "equal" ? r.rLine : ""}
                </td>
                <td className={`whitespace-pre pr-3 ${rightBg}`}>
                  <span
                    className={`inline-block w-3 select-none ${
                      r.kind === "add" ? "text-sev-opt" : "text-fg-muted"
                    }`}
                  >
                    {rightMark}
                  </span>
                  {r.kind === "add" ? (
                    <HighlightedLine line={r.right} />
                  ) : r.kind === "equal" ? (
                    <HighlightedLine line={r.right} />
                  ) : (
                    " "
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Single-pane highlighted source viewer (used by ContractDetail).
export function SyntaxBlock({
  code,
  highlightLines = new Set<number>(),
  lineAnnotations,
}: {
  code: string;
  highlightLines?: Set<number>;
  lineAnnotations?: (line: number) => ReactNode | null;
}) {
  const lines = code.split("\n");
  return (
    <div className="overflow-auto max-h-[520px] text-[11.5px] leading-relaxed font-mono">
      {lines.map((ln, i) => {
        const lineNo = i + 1;
        const flagged = highlightLines.has(lineNo);
        const ann = lineAnnotations?.(lineNo);
        return (
          <div
            key={i}
            className={`flex ${flagged ? "bg-sev-high-bg" : "hover:bg-surface-2/40"}`}
          >
            <span
              className={`w-12 flex-shrink-0 text-right pr-3 select-none border-r border-border/60 ${
                flagged ? "text-sev-high" : "text-fg-muted"
              }`}
            >
              {lineNo}
            </span>
            <span className="px-3 whitespace-pre flex-1 min-w-0">
              <HighlightedLine line={ln || " "} />
            </span>
            {ann && (
              <span className="pr-3 text-2xs text-sev-high/80 self-center font-sans">
                {ann}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
