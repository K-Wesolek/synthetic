"use client";

import { useEffect, useMemo, useState } from "react";
import {
  fetchContractFull,
  type ContractFull,
  type Finding,
} from "@/lib/api";
import {
  Card,
  CardHeader,
  ClassChip,
  CopyButton,
  EmptyState,
  SeverityBadge,
  SeverityDot,
  Skeleton,
  fmtAddress,
  fmtInt,
  fmtUSDCompact,
} from "./ui";
import { SyntaxBlock } from "./solidity";

const CHAIN_LABEL: Record<string, string> = {
  "1": "Ethereum",
  "137": "Polygon",
  "42161": "Arbitrum",
  "10": "Optimism",
  "8453": "Base",
};

function ScoreMeter({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color =
    score >= 0.8
      ? "bg-sev-high"
      : score >= 0.6
        ? "bg-sev-medium"
        : score >= 0.3
          ? "bg-sev-low"
          : "bg-sev-opt";
  return (
    <div className="flex items-center gap-2">
      <div className="w-32 h-1 bg-surface-3 rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="font-mono text-sm tabular-nums text-fg-primary w-10 text-right">
        {score.toFixed(2)}
      </span>
    </div>
  );
}

function annotationsForFile(
  filePath: string,
  findings: Finding[],
): Map<number, Finding[]> {
  const out = new Map<number, Finding[]>();
  for (const f of findings) {
    const marker = f.first_markdown_element || "";
    if (!marker) continue;
    const parts = marker.split("#");
    if (parts.length < 2) continue;
    const fileHint = parts[0];
    if (!filePath.endsWith(fileHint) && !fileHint.endsWith(filePath)) continue;
    const lineMatch = parts[1].match(/L?(\d+)/);
    if (!lineMatch) continue;
    const line = parseInt(lineMatch[1], 10);
    if (!Number.isFinite(line)) continue;
    const list = out.get(line) || [];
    list.push(f);
    out.set(line, list);
  }
  return out;
}

export default function ContractDetail({ contractId }: { contractId: number }) {
  const [data, setData] = useState<ContractFull | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeFile, setActiveFile] = useState<string | null>(null);

  useEffect(() => {
    setData(null);
    setError(null);
    fetchContractFull(contractId)
      .then((d) => {
        setData(d);
        setActiveFile(d.sources[0]?.file_path ?? null);
      })
      .catch((e) =>
        setError(e instanceof Error ? e.message : "load failed"),
      );
  }, [contractId]);

  const activeAnnotations = useMemo(() => {
    if (!data || !activeFile) return new Map<number, Finding[]>();
    return annotationsForFile(activeFile, data.findings);
  }, [data, activeFile]);

  const highlightLines = useMemo(
    () => new Set(activeAnnotations.keys()),
    [activeAnnotations],
  );

  if (error)
    return (
      <div className="bg-sev-high-bg border border-sev-high/30 text-sev-high px-3 py-2 rounded text-sm">
        {error}
      </div>
    );
  if (!data) {
    return (
      <div className="space-y-4 mt-4">
        <Skeleton className="h-28" />
        <Skeleton className="h-40" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  const { contract, score, findings, sources, storage_slots, similar_contracts, related_incidents } = data;
  const activeSource = sources.find((s) => s.file_path === activeFile);

  return (
    <div className="space-y-5 mt-4">
      {/* Header card */}
      <Card className="p-5">
        <div className="flex flex-wrap justify-between gap-6">
          <div className="min-w-0">
            <div className="text-2xs uppercase tracking-wider text-fg-tertiary mb-2 font-mono">
              {CHAIN_LABEL[contract.chain_id] || contract.chain_id} ·{" "}
              {contract.compiler_version || "—"}
              {contract.optimizer_enabled && (
                <>
                  {" "}
                  · optimizer{" "}
                  <span className="text-fg-secondary">
                    {contract.optimizer_runs} runs
                  </span>
                </>
              )}
            </div>
            <h2 className="text-2xl font-medium tracking-tightish text-fg-primary mb-2">
              {contract.contract_name || "Unknown contract"}
            </h2>
            <div className="flex items-center gap-3 font-mono text-xs text-fg-secondary">
              <span title={contract.address}>{contract.address}</span>
              <CopyButton value={contract.address} />
            </div>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className="text-2xs uppercase tracking-wider text-fg-tertiary">
              Risk score
            </div>
            <ScoreMeter score={score.score} />
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5">
                <SeverityDot severity="High" />
                <span className="text-fg-primary">{score.high_count}</span>
                <span className="text-fg-tertiary">high</span>
              </span>
              <span className="flex items-center gap-1.5">
                <SeverityDot severity="Medium" />
                <span className="text-fg-primary">{score.medium_count}</span>
                <span className="text-fg-tertiary">med</span>
              </span>
              <span className="flex items-center gap-1.5">
                <SeverityDot severity="Low" />
                <span className="text-fg-primary">{score.low_count}</span>
                <span className="text-fg-tertiary">low</span>
              </span>
            </div>
          </div>
        </div>

        {score.classes.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-4 pt-4 border-t border-border">
            {score.classes.map((c) => (
              <ClassChip key={c} value={c} />
            ))}
          </div>
        )}
      </Card>

      {/* Findings */}
      {findings.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader
            title={
              <>
                Findings{" "}
                <span className="text-fg-tertiary font-mono text-xs ml-1">
                  ({findings.length})
                </span>
              </>
            }
            subtitle="static analysis · severity · provenance"
          />
          <table className="w-full text-sm">
            <thead className="bg-surface-2">
              <tr>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Detector
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Class
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Severity
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Confidence
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Provenance
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Description
                </th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr
                  key={i}
                  className="even:bg-surface-3/70 hover:bg-surface-3/60 transition-colors"
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-primary">
                    {f.detector}
                  </td>
                  <td className="px-4 py-2.5">
                    <ClassChip value={f.vulnerability_class} />
                  </td>
                  <td className="px-4 py-2.5">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-4 py-2.5">
                    {typeof f.confidence_score === "number" ? (
                      <ScoreMeter score={f.confidence_score} />
                    ) : (
                      <span className="text-fg-muted text-xs">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
                    {f.provenance || "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-secondary max-w-md">
                    {f.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Source viewer */}
      {sources.length > 0 && activeSource && (
        <Card className="overflow-hidden">
          <CardHeader
            title="Source"
            subtitle={`${sources.length} file${sources.length === 1 ? "" : "s"} · highlighted lines map detector markers`}
            right={
              activeSource.truncated ? (
                <span className="text-sev-medium">truncated</span>
              ) : null
            }
          />
          <div className="px-4 py-2 border-b border-border bg-surface-2/40 flex items-center gap-1.5 flex-wrap">
            {sources.map((s) => (
              <button
                key={s.file_path}
                onClick={() => setActiveFile(s.file_path)}
                className={`text-xs font-mono px-2 py-1 rounded transition-colors ${
                  s.file_path === activeFile
                    ? "bg-surface-3 text-fg-primary"
                    : "text-fg-tertiary hover:text-fg-secondary"
                }`}
              >
                {s.file_path}
              </button>
            ))}
          </div>
          <SyntaxBlock
            code={activeSource.content || ""}
            highlightLines={highlightLines}
            lineAnnotations={(line) => {
              const annots = activeAnnotations.get(line);
              if (!annots) return null;
              return (
                <span>
                  ⚠ {annots.map((a) => a.detector).join(", ")}
                </span>
              );
            }}
          />
        </Card>
      )}

      {/* Storage layout */}
      {storage_slots.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader
            title="Storage layout"
            subtitle={`${storage_slots.length} slots`}
          />
          <table className="w-full text-sm">
            <thead className="bg-surface-2">
              <tr>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Slot
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Offset
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Label
                </th>
                <th className="text-left px-4 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                  Type
                </th>
              </tr>
            </thead>
            <tbody>
              {storage_slots.map((s) => (
                <tr key={s.id} className="even:bg-surface-3/70">
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-primary">
                    {s.slot_number}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-fg-tertiary">
                    {s.offset ?? "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-fg-secondary">
                    {s.label || <span className="text-fg-muted">—</span>}
                  </td>
                  <td className="px-4 py-2.5 text-xs font-mono text-fg-secondary">
                    {s.type || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* Similar contracts + related incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader
            title="Similar contracts"
            subtitle="ranked by Jaccard overlap of vulnerability classes"
          />
          <div className="p-2">
            {similar_contracts.length === 0 ? (
              <EmptyState title="No overlapping classes yet." />
            ) : (
              <ul className="space-y-1">
                {similar_contracts.map((s) => (
                  <li
                    key={s.id}
                    className="border border-border rounded p-3 hover:bg-surface-2/40 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3 mb-1">
                      <div className="min-w-0">
                        <div className="text-sm text-fg-primary truncate">
                          {s.contract_name || "Unknown"}
                          <span className="text-fg-tertiary text-xs font-mono ml-2">
                            chain {s.chain_id}
                          </span>
                        </div>
                        <div className="font-mono text-2xs text-fg-tertiary truncate">
                          {s.address}
                        </div>
                      </div>
                      <ScoreMeter score={s.similarity} />
                    </div>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {s.shared_classes.map((c) => (
                        <ClassChip key={c} value={c} />
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Related incidents"
            subtitle="historical anchors sharing this contract's classes"
          />
          <div className="p-2">
            {related_incidents.length === 0 ? (
              <EmptyState title="No incidents share this contract's classes." />
            ) : (
              <ul className="space-y-1">
                {related_incidents.map((i) => (
                  <li
                    key={i.id}
                    className="border border-border rounded p-3 hover:bg-surface-2/40 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-3 mb-1.5">
                      <ClassChip value={i.vulnerability_class} />
                      <span className="text-sm font-mono text-sev-high tabular-nums">
                        {fmtUSDCompact(i.loss_usd)}
                      </span>
                    </div>
                    <div className="text-xs text-fg-secondary leading-relaxed mb-1.5">
                      {i.description}
                    </div>
                    <div className="text-2xs text-fg-tertiary font-mono">
                      {i.incident_date || "—"}
                      {i.source_url && (
                        <>
                          {" · "}
                          <a
                            href={i.source_url}
                            target="_blank"
                            rel="noreferrer"
                            className="hover:text-fg-secondary transition-colors"
                          >
                            source ↗
                          </a>
                        </>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
