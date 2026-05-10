"use client";

import { useState } from "react";
import type { ReactNode } from "react";

// ──────────────────────────────────────────────────────────────────────────
// Number formatters — production grade, never raw integers in the UI.
// ──────────────────────────────────────────────────────────────────────────

export function fmtInt(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  return n.toLocaleString("en-US");
}

export function fmtUSDCompact(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  if (n >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `$${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `$${(n / 1e3).toFixed(1)}k`;
  return `$${n.toFixed(0)}`;
}

export function fmtUSDLong(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "—";
  return `$${n.toLocaleString("en-US", { maximumFractionDigits: 0 })}`;
}

export function fmtAddress(addr?: string | null, head = 6, tail = 4): string {
  if (!addr) return "—";
  if (addr.length <= head + tail + 2) return addr;
  return `${addr.slice(0, 2 + head)}…${addr.slice(-tail)}`;
}

// ──────────────────────────────────────────────────────────────────────────
// Severity primitives
// ──────────────────────────────────────────────────────────────────────────

const SEV_TOKENS: Record<
  string,
  { dot: string; chip: string; text: string }
> = {
  High: {
    dot: "bg-sev-high",
    chip: "bg-sev-high-bg text-sev-high border-sev-high/30",
    text: "text-sev-high",
  },
  Medium: {
    dot: "bg-sev-medium",
    chip: "bg-sev-medium-bg text-sev-medium border-sev-medium/30",
    text: "text-sev-medium",
  },
  Low: {
    dot: "bg-sev-low",
    chip: "bg-sev-low-bg text-sev-low border-sev-low/30",
    text: "text-sev-low",
  },
  Informational: {
    dot: "bg-sev-info",
    chip: "bg-sev-info-bg text-fg-secondary border-border",
    text: "text-fg-secondary",
  },
  Optimization: {
    dot: "bg-sev-opt",
    chip: "bg-sev-opt-bg text-sev-opt border-sev-opt/30",
    text: "text-sev-opt",
  },
};

export const SEVERITY_HEX: Record<string, string> = {
  High: "#e5484d",
  Medium: "#f5a524",
  Low: "#eab308",
  Informational: "#8b8b97",
  Optimization: "#46a758",
};

export function SeverityDot({ severity }: { severity: string | null | undefined }) {
  const t = SEV_TOKENS[severity || "Informational"] || SEV_TOKENS.Informational;
  return <span className={`inline-block w-2 h-2 rounded-full ${t.dot}`} />;
}

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const key = severity || "Informational";
  const t = SEV_TOKENS[key] || SEV_TOKENS.Informational;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded text-2xs uppercase tracking-wider font-medium border ${t.chip}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${t.dot}`} />
      {key}
    </span>
  );
}

export function ClassChip({ value }: { value?: string | null }) {
  if (!value) return null;
  return (
    <span className="inline-flex items-center text-2xs font-mono text-fg-secondary bg-surface-3 border border-border px-1.5 py-0.5 rounded">
      {value}
    </span>
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Section intro — short context block placed at the top of a tab
// ──────────────────────────────────────────────────────────────────────────

export function SectionIntro({
  tags,
  title,
  description,
  meta,
}: {
  tags?: string[];
  title: string;
  description: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5 mb-4">
      <div className="flex flex-wrap items-start justify-between gap-6">
        <div className="max-w-2xl">
          {tags && tags.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 mb-2 text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
              {tags.map((t, i) => (
                <span key={t} className="flex items-center gap-2">
                  {i > 0 && <span className="text-fg-muted">·</span>}
                  <span>{t}</span>
                </span>
              ))}
            </div>
          )}
          <h2 className="font-serif-display text-2xl text-fg-primary leading-tight mb-2">
            {title}
          </h2>
          <p className="text-sm text-fg-secondary leading-relaxed">
            {description}
          </p>
        </div>
        {meta && (
          <div className="font-mono text-2xs text-fg-tertiary space-y-1.5 min-w-[180px]">
            {meta}
          </div>
        )}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Card / Section primitives
// ──────────────────────────────────────────────────────────────────────────

export function Card({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`bg-surface border border-border rounded-lg ${className}`}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  right,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="px-5 py-3 border-b border-border flex items-baseline justify-between gap-3">
      <div>
        <div className="text-sm font-medium text-fg-primary">{title}</div>
        {subtitle && (
          <div className="text-2xs uppercase tracking-wider text-fg-tertiary mt-0.5">
            {subtitle}
          </div>
        )}
      </div>
      {right && <div className="text-2xs text-fg-tertiary">{right}</div>}
    </div>
  );
}

export function EmptyState({
  title,
  description,
}: {
  title: string;
  description?: string;
}) {
  return (
    <div className="border border-dashed border-border rounded-lg p-8 text-center">
      <div className="text-sm text-fg-secondary">{title}</div>
      {description && (
        <div className="text-xs text-fg-tertiary mt-1.5 max-w-md mx-auto">
          {description}
        </div>
      )}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse bg-surface-2 rounded ${className}`}
      aria-hidden
    />
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Copy button
// ──────────────────────────────────────────────────────────────────────────

export function CopyButton({
  value,
  label = "copy",
  className = "",
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          /* ignore */
        }
      }}
      className={`text-2xs uppercase tracking-wider font-mono text-fg-tertiary hover:text-fg-primary transition-colors ${className}`}
      title={`Copy ${value.slice(0, 30)}`}
    >
      {copied ? "copied" : label}
    </button>
  );
}

// ──────────────────────────────────────────────────────────────────────────
// Tooltip helpers for charts
// ──────────────────────────────────────────────────────────────────────────

export const CHART_TOOLTIP_STYLE = {
  background: "rgb(var(--surface-2))",
  border: "1px solid rgb(var(--border-strong))",
  borderRadius: 6,
  color: "rgb(var(--fg-primary))",
  fontSize: 12,
  padding: "8px 10px",
} as const;

export const CHART_AXIS_STYLE = {
  stroke: "rgb(var(--fg-muted))",
  fontSize: 11,
} as const;

// ──────────────────────────────────────────────────────────────────────────
// InfoTip — small hoverable "?" with plain-language description.
// Used to attach glossary entries to charts, hero metrics, and chips.
// ──────────────────────────────────────────────────────────────────────────

export function InfoTip({
  title,
  body,
  children,
  className = "",
  align = "start",
}: {
  title?: string;
  body: ReactNode;
  children?: ReactNode;
  className?: string;
  align?: "start" | "center" | "end";
}) {
  const [open, setOpen] = useState(false);
  const alignCls =
    align === "center"
      ? "left-1/2 -translate-x-1/2"
      : align === "end"
        ? "right-0"
        : "left-0";
  return (
    <span
      className={`relative inline-flex items-center gap-1 ${className}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      tabIndex={0}
    >
      {children ?? (
        <span
          aria-label={title || "info"}
          className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-border text-[9px] font-mono text-fg-tertiary hover:text-fg-primary hover:border-border-strong cursor-help"
        >
          ?
        </span>
      )}
      {open && (
        <span
          role="tooltip"
          className={`absolute z-30 top-full mt-2 w-72 max-w-[80vw] ${alignCls}`}
          style={{
            background: "rgb(var(--surface-2))",
            border: "1px solid rgb(var(--border-strong))",
            borderRadius: 6,
            padding: "10px 12px",
            color: "rgb(var(--fg-primary))",
            fontSize: 12,
            lineHeight: 1.45,
            boxShadow: "0 6px 24px rgba(0,0,0,0.35)",
          }}
        >
          {title && (
            <div className="text-2xs uppercase tracking-wider text-fg-tertiary mb-1.5">
              {title}
            </div>
          )}
          <div className="text-fg-secondary">{body}</div>
        </span>
      )}
    </span>
  );
}
