"use client";

import { useEffect, useState } from "react";
import {
  fetchContract,
  fetchStats,
  searchFindings,
  exportSlice,
  type ContractInfo,
  type Finding,
  type PaymentChallenge,
  type Stats,
} from "@/lib/api";
import Dashboard from "./components/Dashboard";
import Synthetic from "./components/Synthetic";
import Contracts from "./components/Contracts";
import X402Connect from "./components/X402Connect";
import ContractDetail from "./components/ContractDetail";
import { SeverityBadge, fmtUSDCompact, fmtInt, InfoTip, SectionIntro } from "./components/ui";
import { ENTITY_DESCRIPTIONS } from "@/lib/glossary";

function triggerDownload(blob: Blob, name = "benchmark.parquet") {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const CHAINS = [
  { id: "1", name: "Ethereum" },
  { id: "137", name: "Polygon" },
  { id: "42161", name: "Arbitrum" },
  { id: "10", name: "Optimism" },
  { id: "8453", name: "Base" },
];

type Tab =
  | "dashboard"
  | "lookup"
  | "browse"
  | "synthetic"
  | "contracts"
  | "x402";

const TABS: { id: Tab; label: string; hint: string }[] = [
  { id: "dashboard", label: "Atlas", hint: "Vulnerability landscape over the substrate" },
  { id: "contracts", label: "Catalog", hint: "Indexed contracts and historical incidents" },
  { id: "synthetic", label: "Synthetic", hint: "Generated vulnerable / patched pairs" },
  { id: "lookup", label: "Lookup", hint: "Inspect a single contract" },
  { id: "browse", label: "Findings", hint: "Search the finding index" },
  { id: "x402", label: "Agents", hint: "x402 + MCP — paid endpoints" },
];

function HeroStat({
  label,
  value,
  hint,
  tone,
  info,
  infoTitle,
  infoAlign = "start",
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "default" | "danger";
  info?: string;
  infoTitle?: string;
  infoAlign?: "start" | "center" | "end";
}) {
  return (
    <div className="flex flex-col gap-1.5 min-w-[7rem]">
      <span className="text-2xs uppercase tracking-wider text-fg-tertiary inline-flex items-center gap-1.5">
        {label}
        {info && <InfoTip title={infoTitle || label} body={info} align={infoAlign} />}
      </span>
      <span
        className={`font-mono text-3xl md:text-[2.25rem] leading-none font-medium tabular-nums ${
          tone === "danger" ? "text-sev-high" : "text-fg-primary"
        }`}
      >
        {value}
      </span>
      {hint && (
        <span className="text-xs text-fg-tertiary">{hint}</span>
      )}
    </div>
  );
}

function Hero({ stats }: { stats: Stats | null }) {
  return (
    <header className="border-b border-border pb-10 mb-8">
      <div className="flex items-start justify-between gap-4 mb-8">
        <div className="flex items-center gap-2 font-mono text-xs text-fg-tertiary uppercase tracking-widest">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-sev-opt" />
          atlas / evm security
        </div>
        <div className="font-mono text-2xs text-fg-tertiary">
          backend{" "}
          <span className="text-fg-secondary">
            {process.env.NEXT_PUBLIC_API_URL || "127.0.0.1:8000"}
          </span>
          {stats && (
            <>
              <span className="mx-2 text-fg-muted">·</span>
              dataset{" "}
              <span className="text-fg-secondary">
                v{(stats as Stats & { dataset_version?: string }).dataset_version || "0.3.0"}
              </span>
            </>
          )}
        </div>
      </div>

      <h1 className="font-serif-display text-4xl md:text-5xl text-fg-primary max-w-3xl leading-[1.05]">
        Vulnerability landscape over verified Sourcify contracts.
      </h1>
      <p className="text-fg-secondary mt-4 max-w-2xl text-[15px] leading-relaxed">
        An indexed substrate of verified contracts, anchored on historical
        post-mortems and projected forward as synthesized vulnerable / patched
        pairs. Agent-accessible through x402 + MCP.
      </p>

      <div className="mt-10 grid grid-cols-2 md:grid-cols-5 gap-x-8 gap-y-6">
        <HeroStat
          label="Contracts"
          value={stats ? fmtInt(stats.totals.contracts) : "—"}
          hint="verified, indexed"
          info={ENTITY_DESCRIPTIONS.contracts}
        />
        <HeroStat
          label="Findings"
          value={stats ? fmtInt(stats.totals.findings) : "—"}
          hint="static + heuristic"
          info={ENTITY_DESCRIPTIONS.findings}
        />
        <HeroStat
          label="Incidents"
          value={stats ? fmtInt(stats.totals.incidents) : "—"}
          hint="historical anchors"
          info={ENTITY_DESCRIPTIONS.incidents}
        />
        <HeroStat
          label="Synthetic"
          value={stats ? fmtInt(stats.totals.synthetic_cases) : "—"}
          hint="vuln + patch pairs"
          info={ENTITY_DESCRIPTIONS.synthetic}
        />
        <HeroStat
          label="Loss reported"
          value={stats ? fmtUSDCompact(stats.totals.total_loss_usd) : "—"}
          hint="USD on tracked incidents"
          tone="danger"
          info={ENTITY_DESCRIPTIONS.loss}
          infoAlign="end"
        />
      </div>
    </header>
  );
}

export default function Home() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    const handler = () => setTab("x402");
    window.addEventListener("atlas:goto-x402", handler);
    return () => window.removeEventListener("atlas:goto-x402", handler);
  }, []);

  useEffect(() => {
    fetchStats().then(setStats).catch(() => {});
  }, []);

  // Lookup state
  const [chainId, setChainId] = useState("1");
  const [address, setAddress] = useState("");
  const [contract, setContract] = useState<ContractInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Browse state
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [detectorFilter, setDetectorFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [paymentChallenge, setPaymentChallenge] = useState<PaymentChallenge | null>(null);

  async function handleLookup() {
    if (!address.trim()) return;
    setLoading(true);
    setError(null);
    setContract(null);
    try {
      const result = await fetchContract(chainId, address.trim());
      setContract(result.contract);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function handleBrowse() {
    setLoading(true);
    setError(null);
    try {
      const result = await searchFindings({
        detector: detectorFilter || undefined,
        min_severity: severityFilter || undefined,
      });
      setAllFindings(result.results);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function handleExport() {
    setPaymentChallenge(null);
    try {
      const result = await exportSlice({
        detector: detectorFilter || undefined,
        min_severity: severityFilter || undefined,
      });
      if (result.challenge) {
        setPaymentChallenge(result.challenge);
        return;
      }
      if (result.blob) triggerDownload(result.blob);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    }
  }

  return (
    <main className="min-h-screen bg-canvas text-fg-primary">
      <div className="max-w-7xl mx-auto px-6 pt-10 pb-20">
        <Hero stats={stats} />

        {/* Tabs */}
        <nav className="flex gap-6 mb-8 border-b border-border overflow-x-auto -mx-1 px-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`group relative pb-3 text-sm whitespace-nowrap transition-colors ${
                tab === t.id
                  ? "text-fg-primary"
                  : "text-fg-tertiary hover:text-fg-secondary"
              }`}
              title={t.hint}
            >
              {t.label}
              <span
                className={`absolute -bottom-px left-0 right-0 h-px transition-colors ${
                  tab === t.id ? "bg-fg-primary" : "bg-transparent"
                }`}
              />
            </button>
          ))}
        </nav>

        {error && (
          <div className="bg-sev-high-bg border border-sev-high/40 text-sev-high px-4 py-3 rounded text-sm mb-6">
            {error}
          </div>
        )}

        {tab === "dashboard" && <Dashboard />}
        {tab === "synthetic" && <Synthetic />}
        {tab === "contracts" && <Contracts />}
        {tab === "x402" && <X402Connect />}

        {tab === "lookup" && (
          <>
            <SectionIntro
              tags={["per-contract", "score · sources · neighbors"]}
              title="Lookup."
              description="Inspect a single verified contract: aggregated risk score, every detector finding with confidence, source files with detector markers inlined, storage layout, plus the contracts and historical incidents that share its vulnerability classes."
            />
            <div className="flex gap-2 mb-6 flex-wrap">
              <select
                value={chainId}
                onChange={(e) => setChainId(e.target.value)}
                className="bg-surface-2 border border-border rounded px-3 py-2 text-sm text-fg-primary focus:border-border-strong outline-none"
              >
                {CHAINS.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="0x… contract address"
                className="flex-1 min-w-[300px] bg-surface-2 border border-border rounded px-3 py-2 text-sm font-mono text-fg-primary placeholder:text-fg-muted focus:border-border-strong outline-none"
                onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              />
              <button
                onClick={handleLookup}
                disabled={loading}
                className="bg-fg-primary text-canvas hover:bg-fg-secondary disabled:opacity-50 px-5 py-2 rounded text-sm font-medium transition-colors"
              >
                {loading ? "Loading…" : "Lookup"}
              </button>
            </div>

            {!contract && !loading && (
              <div className="border border-dashed border-border rounded-lg p-8 text-center text-fg-tertiary text-sm">
                Enter a verified contract address. Returns metadata, scoring,
                detector findings, source, storage layout, similar contracts and
                related incidents.
              </div>
            )}

            {contract?.id && <ContractDetail contractId={contract.id} />}
          </>
        )}

        {tab === "browse" && (
          <>
            <SectionIntro
              tags={["finding index", "exportable"]}
              title="Findings."
              description="The flat finding stream. Filter by detector or minimum severity; results stream live JSON. Use Export Parquet to materialize a reproducible benchmark slice — paid through x402, $0.01 USDC per slice."
            />
            <div className="flex gap-2 mb-6 flex-wrap">
              <input
                type="text"
                value={detectorFilter}
                onChange={(e) => setDetectorFilter(e.target.value)}
                placeholder="detector (e.g. reentrancy-eth)"
                className="bg-surface-2 border border-border rounded px-3 py-2 text-sm flex-1 min-w-[220px] font-mono text-fg-primary placeholder:text-fg-muted focus:border-border-strong outline-none"
              />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-surface-2 border border-border rounded px-3 py-2 text-sm text-fg-primary focus:border-border-strong outline-none"
              >
                <option value="">all severities</option>
                <option value="High">High+</option>
                <option value="Medium">Medium+</option>
                <option value="Low">Low+</option>
              </select>
              <button
                onClick={handleBrowse}
                disabled={loading}
                className="bg-fg-primary text-canvas hover:bg-fg-secondary disabled:opacity-50 px-5 py-2 rounded text-sm font-medium transition-colors"
              >
                {loading ? "Searching…" : "Search"}
              </button>
              <button
                onClick={handleExport}
                className="border border-border-strong text-fg-secondary hover:text-fg-primary hover:border-fg-tertiary px-5 py-2 rounded text-sm font-medium transition-colors"
                title="x402-gated — pay $0.01 per slice"
              >
                Export Parquet
                <span className="ml-2 text-2xs uppercase tracking-wider text-fg-tertiary">
                  paid
                </span>
              </button>
            </div>

            {paymentChallenge && (
              <div className="mb-6 bg-sev-medium-bg border border-sev-medium/30 rounded-lg p-4 text-sm">
                <div className="text-sev-medium font-medium mb-2">
                  402 Payment Required
                </div>
                <div className="font-mono text-xs space-y-1 text-fg-secondary">
                  <div>
                    price{" "}
                    <span className="text-fg-primary">
                      {paymentChallenge.maxAmountRequired || "0.01 USDC"}
                    </span>
                  </div>
                  <div>
                    network{" "}
                    <span className="text-fg-primary">
                      {paymentChallenge.network || "Base Sepolia"}
                    </span>
                  </div>
                  <div className="break-all">
                    pay-to{" "}
                    <span className="text-fg-primary">{paymentChallenge.payTo}</span>
                  </div>
                </div>
                <p className="text-xs text-fg-tertiary mt-3">
                  Set <code className="font-mono text-fg-secondary">NEXT_PUBLIC_WALLET_PRIVATE_KEY</code>{" "}
                  with a funded Base Sepolia wallet to auto-pay on retry.
                </p>
              </div>
            )}

            {allFindings.length === 0 && !loading && (
              <div className="border border-dashed border-border rounded-lg p-8 text-center text-fg-tertiary text-sm">
                Filter and search the finding index. Results stream as JSON;
                Export → Parquet for benchmark slices.
              </div>
            )}

            {allFindings.length > 0 && (
              <div className="bg-surface border border-border rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-border flex items-baseline justify-between">
                  <h3 className="text-sm font-medium">
                    Findings{" "}
                    <span className="text-fg-tertiary font-mono">
                      ({fmtInt(allFindings.length)})
                    </span>
                  </h3>
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-surface-2">
                    <tr>
                      <th className="text-left px-5 py-2.5 text-2xs uppercase text-fg-tertiary font-medium">
                        Contract
                      </th>
                      <th className="text-left px-5 py-2.5 text-2xs uppercase text-fg-tertiary font-medium">
                        Address
                      </th>
                      <th className="text-left px-5 py-2.5 text-2xs uppercase text-fg-tertiary font-medium">
                        Detector
                      </th>
                      <th className="text-left px-5 py-2.5 text-2xs uppercase text-fg-tertiary font-medium">
                        Severity
                      </th>
                      <th className="text-left px-5 py-2.5 text-2xs uppercase text-fg-tertiary font-medium">
                        Description
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {allFindings.map((f, i) => (
                      <tr
                        key={i}
                        className="even:bg-surface-3/70 hover:bg-surface-3/60 transition-colors"
                      >
                        <td className="px-5 py-2.5 text-fg-secondary">
                          {f.contract_name || "—"}
                        </td>
                        <td className="px-5 py-2.5 font-mono text-xs text-fg-tertiary truncate max-w-[160px]">
                          {f.address?.slice(0, 10)}…{f.address?.slice(-4)}
                        </td>
                        <td className="px-5 py-2.5 font-mono text-xs">
                          {f.detector}
                        </td>
                        <td className="px-5 py-2.5">
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="px-5 py-2.5 text-fg-secondary text-xs max-w-md truncate">
                          {f.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </main>
  );
}
