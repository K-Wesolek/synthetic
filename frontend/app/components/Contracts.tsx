"use client";

import { useEffect, useMemo, useState } from "react";
import {
  fetchContracts,
  fetchIncidents,
  type ContractInfo,
  type Incident,
} from "@/lib/api";
import {
  detailFor,
  INJECTED_INCIDENTS,
} from "@/lib/incident-details";
import {
  Card,
  CardHeader,
  ClassChip,
  CopyButton,
  EmptyState,
  SectionIntro,
  Skeleton,
  fmtAddress,
  fmtInt,
  fmtUSDCompact,
} from "./ui";
import IncidentModal from "./IncidentModal";

const CHAIN_LABEL: Record<string, string> = {
  "1": "Ethereum",
  "137": "Polygon",
  "42161": "Arbitrum",
  "10": "Optimism",
  "8453": "Base",
};

type SortKey = "name" | "address" | "chain" | "compiler" | "high" | "medium" | "total";
type SortDir = "asc" | "desc";

function SortHeader({
  label,
  active,
  dir,
  onClick,
  align = "left",
}: {
  label: string;
  active: boolean;
  dir: SortDir;
  onClick: () => void;
  align?: "left" | "right";
}) {
  return (
    <th
      onClick={onClick}
      className={`px-5 py-2.5 text-2xs uppercase tracking-wider font-medium cursor-pointer select-none transition-colors ${
        align === "right" ? "text-right" : "text-left"
      } ${active ? "text-fg-primary" : "text-fg-tertiary hover:text-fg-secondary"}`}
    >
      <span className="inline-flex items-center gap-1.5">
        {label}
        <span
          className={`text-[8px] leading-none transition-opacity ${
            active ? "opacity-100" : "opacity-30"
          }`}
        >
          {active ? (dir === "asc" ? "▲" : "▼") : "▼"}
        </span>
      </span>
    </th>
  );
}

export default function Contracts() {
  const [contracts, setContracts] = useState<ContractInfo[] | null>(null);
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [chainFilter, setChainFilter] = useState<string>("");
  const [sortKey, setSortKey] = useState<SortKey>("high");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [openIncident, setOpenIncident] = useState<Incident | null>(null);

  useEffect(() => {
    Promise.all([fetchContracts(500), fetchIncidents()])
      .then(([c, i]) => {
        setContracts(c.results);
        // Prepend curated incidents (e.g. Kelp DAO) to the API list,
        // de-duped by tx_hash so a future backend seed doesn't double them.
        const apiHashes = new Set(
          i.results.map((x) => x.tx_hash).filter(Boolean) as string[],
        );
        const injected = INJECTED_INCIDENTS.filter(
          (x) => !x.tx_hash || !apiHashes.has(x.tx_hash),
        );
        setIncidents([...injected, ...i.results]);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));
  }, []);

  const allChains = useMemo(() => {
    if (!contracts) return [];
    return Array.from(new Set(contracts.map((c) => c.chain_id))).sort();
  }, [contracts]);

  const visibleContracts = useMemo(() => {
    if (!contracts) return [];
    const q = filter.trim().toLowerCase();
    let out = contracts.filter((c) => {
      if (chainFilter && c.chain_id !== chainFilter) return false;
      if (!q) return true;
      return (
        (c.contract_name || "").toLowerCase().includes(q) ||
        c.address.toLowerCase().includes(q) ||
        (c.compiler_version || "").toLowerCase().includes(q)
      );
    });
    out = [...out].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      const av: string | number = (() => {
        switch (sortKey) {
          case "name":
            return (a.contract_name || "").toLowerCase();
          case "address":
            return a.address.toLowerCase();
          case "chain":
            return a.chain_id;
          case "compiler":
            return a.compiler_version || "";
          case "high":
            return a.high_count ?? 0;
          case "medium":
            return a.medium_count ?? 0;
          case "total":
            return a.finding_count ?? 0;
        }
      })();
      const bv: string | number = (() => {
        switch (sortKey) {
          case "name":
            return (b.contract_name || "").toLowerCase();
          case "address":
            return b.address.toLowerCase();
          case "chain":
            return b.chain_id;
          case "compiler":
            return b.compiler_version || "";
          case "high":
            return b.high_count ?? 0;
          case "medium":
            return b.medium_count ?? 0;
          case "total":
            return b.finding_count ?? 0;
        }
      })();
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    });
    return out;
  }, [contracts, filter, chainFilter, sortKey, sortDir]);

  function clickHeader(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir(k === "name" || k === "address" || k === "chain" || k === "compiler" ? "asc" : "desc");
    }
  }

  if (error)
    return (
      <div className="bg-sev-high-bg border border-sev-high/30 text-sev-high px-3 py-2 rounded text-sm">
        {error}
      </div>
    );

  return (
    <div className="space-y-6">
      <SectionIntro
        tags={["sourcify", "post-mortems"]}
        title="Catalog."
        description="Historical incidents that anchor the synthetic generator, plus every verified contract ingested from Sourcify. Click any incident row for the technical + plain-language post-mortem; click an address in the contract list to copy."
      />

      {/* Incidents — moved above contracts; rows open a detail modal */}
      <Card className="overflow-hidden">
        <CardHeader
          title={
            <>
              Incidents{" "}
              <span className="text-fg-tertiary font-mono text-xs ml-1">
                ({incidents ? fmtInt(incidents.length) : "…"})
              </span>
            </>
          }
          right="click row for full post-mortem"
        />
        <div className="overflow-auto max-h-[520px]">
          {!incidents && (
            <div className="p-5 space-y-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-5" />
              ))}
            </div>
          )}
          {incidents && incidents.length === 0 && (
            <EmptyState title="No incidents indexed yet." />
          )}
          {incidents && incidents.length > 0 && (
            <table className="w-full text-sm">
              <thead className="bg-surface-2 sticky top-0">
                <tr>
                  <th className="text-left px-5 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                    Date
                  </th>
                  <th className="text-left px-5 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                    Class
                  </th>
                  <th className="text-right px-5 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                    Loss
                  </th>
                  <th className="text-left px-5 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary">
                    Description
                  </th>
                  <th className="text-right px-5 py-2.5 text-2xs uppercase tracking-wider font-medium text-fg-tertiary w-20">
                    Detail
                  </th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((i) => {
                  const hasDetail = !!detailFor(i);
                  return (
                    <tr
                      key={i.id}
                      onClick={() => setOpenIncident(i)}
                      className="even:bg-surface-3/70 hover:bg-surface-3/60 transition-colors cursor-pointer"
                    >
                      <td className="px-5 py-2.5 font-mono text-xs text-fg-tertiary">
                        {i.incident_date || "—"}
                      </td>
                      <td className="px-5 py-2.5">
                        <ClassChip value={i.vulnerability_class} />
                      </td>
                      <td className="px-5 py-2.5 text-right font-mono text-xs text-sev-high">
                        {fmtUSDCompact(i.loss_usd)}
                      </td>
                      <td className="px-5 py-2.5 text-fg-secondary text-xs max-w-md">
                        {i.description}
                      </td>
                      <td className="px-5 py-2.5 text-right">
                        <span
                          className={`text-2xs uppercase tracking-wider font-mono ${
                            hasDetail
                              ? "text-fg-secondary"
                              : "text-fg-muted"
                          }`}
                        >
                          {hasDetail ? "open ↗" : "open"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      {/* Filter bar */}
      <div className="flex flex-wrap gap-2 items-center">
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter by name, address, compiler…"
          className="bg-surface-2 border border-border rounded px-3 py-2 text-sm flex-1 min-w-[260px] text-fg-primary placeholder:text-fg-muted focus:border-border-strong outline-none"
        />
        <select
          value={chainFilter}
          onChange={(e) => setChainFilter(e.target.value)}
          className="bg-surface-2 border border-border rounded px-3 py-2 text-sm text-fg-primary focus:border-border-strong outline-none"
        >
          <option value="">all chains</option>
          {allChains.map((id) => (
            <option key={id} value={id}>
              {CHAIN_LABEL[id] || id}
            </option>
          ))}
        </select>
        <span className="text-2xs uppercase tracking-wider text-fg-tertiary ml-1">
          {contracts ? `${visibleContracts.length} / ${contracts.length}` : "…"}
        </span>
      </div>

      {/* Contracts table */}
      <Card className="overflow-hidden">
        <CardHeader
          title={
            <>
              Indexed contracts{" "}
              <span className="text-fg-tertiary font-mono text-xs ml-1">
                ({contracts ? fmtInt(contracts.length) : "…"})
              </span>
            </>
          }
          right="sort by clicking columns"
        />
        <div className="overflow-auto max-h-[460px]">
          <table className="w-full text-sm">
            <thead className="bg-surface-2 sticky top-0 z-10">
              <tr>
                <SortHeader
                  label="Name"
                  active={sortKey === "name"}
                  dir={sortDir}
                  onClick={() => clickHeader("name")}
                />
                <SortHeader
                  label="Address"
                  active={sortKey === "address"}
                  dir={sortDir}
                  onClick={() => clickHeader("address")}
                />
                <SortHeader
                  label="Chain"
                  active={sortKey === "chain"}
                  dir={sortDir}
                  onClick={() => clickHeader("chain")}
                />
                <SortHeader
                  label="Compiler"
                  active={sortKey === "compiler"}
                  dir={sortDir}
                  onClick={() => clickHeader("compiler")}
                />
                <SortHeader
                  label="High"
                  active={sortKey === "high"}
                  dir={sortDir}
                  onClick={() => clickHeader("high")}
                  align="right"
                />
                <SortHeader
                  label="Med"
                  active={sortKey === "medium"}
                  dir={sortDir}
                  onClick={() => clickHeader("medium")}
                  align="right"
                />
                <SortHeader
                  label="Total"
                  active={sortKey === "total"}
                  dir={sortDir}
                  onClick={() => clickHeader("total")}
                  align="right"
                />
              </tr>
            </thead>
            <tbody>
              {!contracts &&
                Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} className="hover:bg-surface-2/60 transition-colors">
                    <td colSpan={7} className="px-5 py-3">
                      <Skeleton className="h-4" />
                    </td>
                  </tr>
                ))}
              {contracts && visibleContracts.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="px-5 py-8 text-center text-fg-tertiary text-sm">
                      No contracts match the filter.
                    </div>
                  </td>
                </tr>
              )}
              {visibleContracts.map((c) => (
                <tr
                  key={c.id}
                  className="even:bg-surface-3/70 hover:bg-surface-3/60 transition-colors group"
                >
                  <td className="px-5 py-2.5 text-fg-primary">
                    {c.contract_name || (
                      <span className="text-fg-muted">—</span>
                    )}
                  </td>
                  <td className="px-5 py-2.5 font-mono text-xs text-fg-secondary">
                    <span className="inline-flex items-center gap-2">
                      <span title={c.address}>{fmtAddress(c.address, 6, 4)}</span>
                      <CopyButton
                        value={c.address}
                        className="opacity-0 group-hover:opacity-100"
                      />
                    </span>
                  </td>
                  <td className="px-5 py-2.5 text-fg-tertiary text-xs">
                    {CHAIN_LABEL[c.chain_id] || c.chain_id}
                  </td>
                  <td className="px-5 py-2.5 font-mono text-xs text-fg-tertiary">
                    {c.compiler_version || "—"}
                  </td>
                  <td className="px-5 py-2.5 text-right font-mono text-xs">
                    {c.high_count ? (
                      <span className="text-sev-high">{c.high_count}</span>
                    ) : (
                      <span className="text-fg-muted">0</span>
                    )}
                  </td>
                  <td className="px-5 py-2.5 text-right font-mono text-xs">
                    {c.medium_count ? (
                      <span className="text-sev-medium">{c.medium_count}</span>
                    ) : (
                      <span className="text-fg-muted">0</span>
                    )}
                  </td>
                  <td className="px-5 py-2.5 text-right font-mono text-xs text-fg-primary">
                    {c.finding_count ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <IncidentModal
        open={!!openIncident}
        incident={openIncident}
        onClose={() => setOpenIncident(null)}
      />
    </div>
  );
}
