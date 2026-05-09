"use client";

import { useState } from "react";
import {
  fetchContract,
  searchFindings,
  exportSlice,
  type ContractInfo,
  type Finding,
  type PaymentChallenge,
} from "@/lib/api";

function triggerDownload(blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "benchmark.parquet";
  a.click();
  URL.revokeObjectURL(url);
}

const CHAINS = [
  { id: "1", name: "Ethereum Mainnet" },
  { id: "137", name: "Polygon" },
  { id: "42161", name: "Arbitrum One" },
  { id: "10", name: "Optimism" },
  { id: "8453", name: "Base" },
];

const SEVERITY_COLORS: Record<string, string> = {
  High: "bg-red-100 text-red-800",
  Medium: "bg-yellow-100 text-yellow-800",
  Low: "bg-blue-100 text-blue-800",
  Informational: "bg-gray-100 text-gray-700",
  Optimization: "bg-green-100 text-green-800",
};

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] || "bg-gray-100 text-gray-700";
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {severity}
    </span>
  );
}

export default function Home() {
  const [chainId, setChainId] = useState("1");
  const [address, setAddress] = useState("");
  const [contract, setContract] = useState<ContractInfo | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [allFindings, setAllFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectorFilter, setDetectorFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [paymentChallenge, setPaymentChallenge] = useState<PaymentChallenge | null>(null);
  const [tab, setTab] = useState<"lookup" | "browse">("lookup");

  async function handleSearch() {
    if (!address.trim()) return;
    setLoading(true);
    setError(null);
    setContract(null);
    setFindings([]);
    try {
      const result = await fetchContract(chainId, address.trim());
      setContract(result.contract);
      setFindings(result.findings);
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
      if (result.blob) {
        triggerDownload(result.blob);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Export failed");
    }
  }

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100">
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Header */}
        <h1 className="text-3xl font-bold mb-2">EVM Security Atlas</h1>
        <p className="text-gray-400 mb-8">
          Vulnerability intelligence over verified Sourcify contracts
        </p>

        {/* Tabs */}
        <div className="flex gap-4 mb-6 border-b border-gray-800">
          <button
            className={`pb-2 px-1 text-sm font-medium ${
              tab === "lookup"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-gray-500 hover:text-gray-300"
            }`}
            onClick={() => setTab("lookup")}
          >
            Contract Lookup
          </button>
          <button
            className={`pb-2 px-1 text-sm font-medium ${
              tab === "browse"
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-gray-500 hover:text-gray-300"
            }`}
            onClick={() => {
              setTab("browse");
              if (allFindings.length === 0) handleBrowse();
            }}
          >
            Browse Findings
          </button>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 text-red-300 px-4 py-3 rounded mb-6">
            {error}
          </div>
        )}

        {/* Contract Lookup Tab */}
        {tab === "lookup" && (
          <>
            <div className="flex gap-3 mb-6">
              <select
                value={chainId}
                onChange={(e) => setChainId(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
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
                placeholder="0x contract address..."
                className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono"
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              />
              <button
                onClick={handleSearch}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-6 py-2 rounded text-sm font-medium"
              >
                {loading ? "Loading..." : "Lookup"}
              </button>
            </div>

            {contract && (
              <div className="mb-6 bg-gray-900 border border-gray-800 rounded-lg p-5">
                <h2 className="text-lg font-semibold mb-3">
                  {contract.contract_name || "Unknown Contract"}
                </h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-500">Address</span>
                    <p className="font-mono text-xs mt-1 truncate">{contract.address}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Chain</span>
                    <p className="mt-1">{CHAINS.find(c => c.id === contract.chain_id)?.name || contract.chain_id}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Compiler</span>
                    <p className="mt-1 font-mono text-xs">{contract.compiler_version || "N/A"}</p>
                  </div>
                  <div>
                    <span className="text-gray-500">Optimizer</span>
                    <p className="mt-1">
                      {contract.optimizer_enabled
                        ? `Enabled (${contract.optimizer_runs} runs)`
                        : "Disabled"}
                    </p>
                  </div>
                </div>

                {contract.storage_layout &&
                  typeof contract.storage_layout === "object" &&
                  "storage" in contract.storage_layout &&
                  Array.isArray((contract.storage_layout as Record<string, unknown>).storage) &&
                  ((contract.storage_layout as Record<string, unknown[]>).storage).length > 0 && (
                    <details className="mt-4">
                      <summary className="text-gray-400 cursor-pointer text-sm">
                        Storage Layout ({((contract.storage_layout as Record<string, unknown[]>).storage).length} slots)
                      </summary>
                      <pre className="mt-2 text-xs bg-gray-950 p-3 rounded overflow-auto max-h-48">
                        {JSON.stringify(contract.storage_layout, null, 2)}
                      </pre>
                    </details>
                  )}
              </div>
            )}

            {findings.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-800">
                  <h3 className="font-medium">
                    Findings ({findings.length})
                  </h3>
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-gray-800/50">
                    <tr>
                      <th className="text-left px-5 py-2 text-gray-400">Detector</th>
                      <th className="text-left px-5 py-2 text-gray-400">Severity</th>
                      <th className="text-left px-5 py-2 text-gray-400">Confidence</th>
                      <th className="text-left px-5 py-2 text-gray-400">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => (
                      <tr key={i} className="border-t border-gray-800/50 hover:bg-gray-800/30">
                        <td className="px-5 py-3 font-mono text-xs">{f.detector}</td>
                        <td className="px-5 py-3"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-5 py-3 text-gray-400">{f.confidence || "N/A"}</td>
                        <td className="px-5 py-3 text-gray-300 text-xs">{f.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* Browse Findings Tab */}
        {tab === "browse" && (
          <>
            <div className="flex gap-3 mb-6 flex-wrap">
              <input
                type="text"
                value={detectorFilter}
                onChange={(e) => setDetectorFilter(e.target.value)}
                placeholder="Filter by detector (e.g. reentrancy-eth)..."
                className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm flex-1 min-w-[200px]"
              />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm"
              >
                <option value="">All Severities</option>
                <option value="High">High+</option>
                <option value="Medium">Medium+</option>
                <option value="Low">Low+</option>
              </select>
              <button
                onClick={handleBrowse}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-6 py-2 rounded text-sm font-medium"
              >
                {loading ? "Searching..." : "Search"}
              </button>
              <button
                onClick={handleExport}
                className="bg-emerald-600 hover:bg-emerald-700 px-6 py-2 rounded text-sm font-medium"
              >
                Export Parquet
              </button>
            </div>

            {/* x402 Payment Modal */}
            {paymentChallenge && (
              <div className="mb-6 bg-yellow-900/20 border border-yellow-700 rounded-lg p-5">
                <h3 className="font-medium text-yellow-300 mb-2">Payment Required (x402)</h3>
                <p className="text-sm text-gray-300 mb-1">
                  Cost: {paymentChallenge.maxAmountRequired || "0.01 USDC"}
                </p>
                <p className="text-sm text-gray-400 mb-1 font-mono">
                  Pay to: {paymentChallenge.payTo || "N/A"}
                </p>
                <p className="text-sm text-gray-400 mb-3">
                  Network: {paymentChallenge.network || "Base Sepolia"}
                </p>
                <p className="text-xs text-gray-500">
                  Set <code>NEXT_PUBLIC_WALLET_PRIVATE_KEY</code> with a funded Base Sepolia wallet to pay automatically.
                </p>
              </div>
            )}

            {allFindings.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-800">
                  <h3 className="font-medium">
                    Results ({allFindings.length})
                  </h3>
                </div>
                <table className="w-full text-sm">
                  <thead className="bg-gray-800/50">
                    <tr>
                      <th className="text-left px-5 py-2 text-gray-400">Contract</th>
                      <th className="text-left px-5 py-2 text-gray-400">Address</th>
                      <th className="text-left px-5 py-2 text-gray-400">Detector</th>
                      <th className="text-left px-5 py-2 text-gray-400">Severity</th>
                      <th className="text-left px-5 py-2 text-gray-400">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {allFindings.map((f, i) => (
                      <tr key={i} className="border-t border-gray-800/50 hover:bg-gray-800/30">
                        <td className="px-5 py-3 text-xs">{f.contract_name || "Unknown"}</td>
                        <td className="px-5 py-3 font-mono text-xs truncate max-w-[120px]">
                          {f.address}
                        </td>
                        <td className="px-5 py-3 font-mono text-xs">{f.detector}</td>
                        <td className="px-5 py-3"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-5 py-3 text-gray-300 text-xs max-w-xs truncate">
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
