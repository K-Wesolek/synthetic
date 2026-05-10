"use client";

import { useEffect, useState, type ReactNode } from "react";
import {
  callMcpTool,
  exportSlice,
  fetchX402Catalog,
  type PaymentChallenge,
  type X402Catalog,
} from "@/lib/api";
import { Card, CardHeader, CopyButton, Skeleton, fmtAddress } from "./ui";

const API_BASE =
  (typeof process !== "undefined" && process.env.NEXT_PUBLIC_API_URL) ||
  "http://localhost:8000";

type Lang = "ts" | "py" | "curl" | "mcp";

const LANG_LABEL: Record<Lang, string> = {
  ts: "TypeScript",
  py: "Python",
  curl: "curl",
  mcp: "MCP manifest",
};

function CodeBlock({
  code,
  lang,
  className = "",
}: {
  code: string;
  lang?: string;
  className?: string;
}) {
  return (
    <div
      className={`relative bg-surface-2 border border-border rounded-md overflow-hidden ${className}`}
    >
      <div className="absolute right-2 top-2 z-10">
        <CopyButton value={code} />
      </div>
      <pre className="p-4 pr-16 text-[11.5px] leading-relaxed text-fg-primary overflow-x-auto font-mono">
        <code data-lang={lang}>{code}</code>
      </pre>
    </div>
  );
}

function StatRow({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-2 font-mono text-xs">
      {children}
    </div>
  );
}

export default function X402Connect() {
  const [catalog, setCatalog] = useState<X402Catalog | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Live demo state
  const [challenge, setChallenge] = useState<PaymentChallenge | null>(null);
  const [demoBusy, setDemoBusy] = useState(false);
  const [mcpResult, setMcpResult] = useState<unknown>(null);
  const [demoLog, setDemoLog] = useState<string[]>([]);

  // Recipe tab
  const [lang, setLang] = useState<Lang>("ts");

  useEffect(() => {
    fetchX402Catalog()
      .then(setCatalog)
      .catch((e) => setError(e instanceof Error ? e.message : "catalog load failed"));
  }, []);

  function log(line: string) {
    setDemoLog((prev) => [...prev.slice(-19), line]);
  }

  async function tryExport() {
    setDemoBusy(true);
    setChallenge(null);
    log("→ POST /api/export (no wallet attached)");
    try {
      const res = await exportSlice({ min_severity: "High" });
      if (res.challenge) {
        setChallenge(res.challenge);
        log(
          `← 402 ${res.challenge.maxAmountRequired} on ${res.challenge.network}`,
        );
      } else if (res.blob) {
        log(`← 200 OK · ${res.blob.size} bytes parquet`);
      }
    } catch (e) {
      log(`× ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDemoBusy(false);
    }
  }

  async function tryMcp() {
    setDemoBusy(true);
    setMcpResult(null);
    log("→ POST /api/mcp { tool: list_synthetic_cases }");
    try {
      const r = await callMcpTool("list_synthetic_cases", { limit: 3 });
      if (r.challenge) {
        setChallenge(r.challenge);
        log(
          `← 402 ${r.challenge.maxAmountRequired} on ${r.challenge.network}`,
        );
      } else {
        setMcpResult(r.response?.data);
        const arr = Array.isArray(r.response?.data) ? r.response.data : [];
        log(`← 200 OK · ${arr.length} cases`);
      }
    } catch (e) {
      log(`× ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDemoBusy(false);
    }
  }

  if (error)
    return (
      <div className="bg-sev-high-bg border border-sev-high/30 text-sev-high px-4 py-3 rounded text-sm">
        {error}
      </div>
    );

  if (!catalog) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-48" />
      </div>
    );
  }

  const tsClient = `import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const signer = privateKeyToAccount(process.env.WALLET_PRIVATE_KEY as \`0x\${string}\`);
const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(signer));
const paidFetch = wrapFetchWithPayment(fetch, client);

// Pull a high-severity slice as Parquet
const r = await paidFetch("${API_BASE}/api/export", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ min_severity: "High" }),
});
const parquet = await r.arrayBuffer();

// Or call any MCP tool — same wallet, per-call billing
const m = await paidFetch("${API_BASE}/api/mcp", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    tool: "search_vulnerabilities",
    args: { min_severity: "High" },
  }),
});`;

  const pyClient = `from x402.client import X402Client
from x402.evm.exact.client import ExactEvmScheme
from eth_account import Account
import os

signer = Account.from_key(os.environ["WALLET_PRIVATE_KEY"])
client = X402Client()
client.register("eip155:*", ExactEvmScheme(signer))

resp = client.post(
    "${API_BASE}/api/mcp",
    json={"tool": "search_vulnerabilities", "args": {"min_severity": "High"}},
)
findings = resp.json()["data"]`;

  const curl = `# 1. Discover the price (no wallet)
curl -i -X POST ${API_BASE}/api/export \\
  -H 'Content-Type: application/json' \\
  -d '{"min_severity":"High"}'
# → HTTP/1.1 402 Payment Required
#   payment-required: <base64 challenge>

# 2. Sign with x402 SDK and retry — receive the parquet bytes`;

  const mcpManifest = JSON.stringify(
    {
      mcpServers: {
        "evm-security-atlas": {
          url: `${API_BASE}/api/mcp`,
          payment: {
            scheme: "x402",
            network: catalog.network,
            payTo: catalog.pay_to,
          },
          tools: catalog.tools.map((t) => t.name),
        },
      },
    },
    null,
    2,
  );

  const recipes: Record<Lang, string> = {
    ts: tsClient,
    py: pyClient,
    curl,
    mcp: mcpManifest,
  };

  const walletPresent = !!process.env.NEXT_PUBLIC_WALLET_PRIVATE_KEY;

  return (
    <div className="space-y-6">
      {/* Header card — no gradient. Just data. */}
      <Card className="p-5">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 mb-2 text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
              <span>x402</span>
              <span className="text-fg-muted">·</span>
              <span>mcp</span>
              <span className="text-fg-muted">·</span>
              <span>per-call billing</span>
            </div>
            <h2 className="font-serif-display text-2xl text-fg-primary leading-tight mb-2">
              Connect your agent.
            </h2>
            <p className="text-sm text-fg-secondary leading-relaxed">
              The Atlas exposes its paid surfaces — Parquet export and MCP tool
              calls — through the x402 HTTP-payment scheme. Wrap any fetch with a
              wallet-bearing client; sign the 402 challenge; the same call returns
              200 with the dataset. No accounts, no API keys.
            </p>
          </div>
          <div className="font-mono text-2xs space-y-1.5">
            <StatRow>
              <span className="text-fg-tertiary uppercase tracking-wider">Network</span>
              <span className="text-fg-primary">{catalog.network}</span>
            </StatRow>
            <StatRow>
              <span className="text-fg-tertiary uppercase tracking-wider">Pay-to</span>
              <span className="text-fg-primary" title={catalog.pay_to}>
                {fmtAddress(catalog.pay_to, 6, 4)}
              </span>
              <CopyButton value={catalog.pay_to} />
            </StatRow>
            <StatRow>
              <span className="text-fg-tertiary uppercase tracking-wider">Facilitator</span>
              <span className="text-fg-primary">x402.org</span>
            </StatRow>
            {catalog.dataset_version && (
              <StatRow>
                <span className="text-fg-tertiary uppercase tracking-wider">Dataset</span>
                <span className="text-fg-primary">v{catalog.dataset_version}</span>
                {catalog.taxonomy_version && (
                  <span className="text-fg-tertiary">
                    · taxonomy v{catalog.taxonomy_version}
                  </span>
                )}
              </StatRow>
            )}
          </div>
        </div>
      </Card>

      {/* Endpoint catalog */}
      <Card>
        <CardHeader title="Endpoints" subtitle="paid surfaces" />
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border">
          {catalog.endpoints.map((e) => (
            <div key={e.id} className="p-5">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-2xs uppercase font-mono px-1.5 py-0.5 bg-surface-3 border border-border text-fg-secondary rounded">
                    {e.method}
                  </span>
                  <span className="font-mono text-sm text-fg-primary">{e.path}</span>
                </div>
                <span className="text-sm font-mono text-sev-opt tabular-nums">
                  {e.price}
                </span>
              </div>
              <p className="text-xs text-fg-secondary leading-relaxed mb-2">
                {e.description}
              </p>
              <p className="text-2xs uppercase tracking-wider text-fg-tertiary font-mono">
                {e.mime_type}
              </p>
            </div>
          ))}
        </div>
      </Card>

      {/* Tool registry */}
      <Card>
        <CardHeader
          title="MCP tools"
          subtitle={`${catalog.tools.length} tools · billed at ${catalog.endpoints.find((e) => e.id === "mcp")?.price} per call`}
        />
        <div className="grid grid-cols-1 md:grid-cols-2">
          {catalog.tools.map((t, i) => (
            <div
              key={t.name}
              className={`p-4 ${i >= 1 ? "border-t border-border" : ""} ${i % 2 === 1 ? "md:border-l md:border-border" : ""}`}
            >
              <div className="font-mono text-sm text-fg-primary">{t.name}</div>
              <div className="text-xs text-fg-secondary mt-1 mb-2 leading-relaxed">
                {t.description}
              </div>
              <div className="text-2xs font-mono text-fg-tertiary break-words">
                {Object.keys(t.args).length === 0 ? (
                  "(no args)"
                ) : (
                  <>
                    args:{" "}
                    {Object.entries(t.args).map(([k, v], i) => (
                      <span key={k}>
                        {i > 0 && ", "}
                        <span className="text-fg-secondary">{k}</span>
                        <span className="text-fg-muted">: {v}</span>
                      </span>
                    ))}
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Live demo */}
      <Card>
        <CardHeader
          title="Live demo"
          subtitle="hit a paid endpoint right now from this browser"
          right={
            <span className="font-mono">
              wallet{" "}
              {walletPresent ? (
                <span className="text-sev-opt">attached · auto-pay</span>
              ) : (
                <span className="text-sev-medium">absent · 402 surfaced</span>
              )}
            </span>
          }
        />
        <div className="p-5">
          <div className="flex flex-wrap gap-2 mb-4">
            <button
              onClick={tryExport}
              disabled={demoBusy}
              className="border border-border-strong text-fg-secondary hover:text-fg-primary hover:border-fg-tertiary disabled:opacity-50 px-4 py-2 rounded text-sm font-medium transition-colors"
            >
              {demoBusy ? "calling…" : "POST /api/export"}
            </button>
            <button
              onClick={tryMcp}
              disabled={demoBusy}
              className="border border-border-strong text-fg-secondary hover:text-fg-primary hover:border-fg-tertiary disabled:opacity-50 px-4 py-2 rounded text-sm font-medium transition-colors"
            >
              {demoBusy ? "calling…" : "POST /api/mcp · list_synthetic_cases"}
            </button>
          </div>

          {challenge && (
            <div className="mb-3 bg-sev-medium-bg border border-sev-medium/30 rounded-md p-3">
              <div className="text-sev-medium text-sm font-medium mb-2">
                402 Payment Required
              </div>
              <div className="text-2xs font-mono space-y-0.5 text-fg-secondary">
                <div>
                  <span className="text-fg-tertiary">price </span>
                  <span className="text-fg-primary">
                    {challenge.maxAmountRequired || "—"}
                  </span>
                </div>
                <div>
                  <span className="text-fg-tertiary">network </span>
                  <span className="text-fg-primary">{challenge.network}</span>
                </div>
                <div className="break-all">
                  <span className="text-fg-tertiary">pay-to </span>
                  <span className="text-fg-primary">{challenge.payTo}</span>
                </div>
                <div>
                  <span className="text-fg-tertiary">scheme </span>
                  <span className="text-fg-primary">{challenge.scheme}</span>
                </div>
              </div>
              <div className="text-2xs text-fg-tertiary mt-2.5">
                Set{" "}
                <code className="font-mono text-fg-secondary">
                  NEXT_PUBLIC_WALLET_PRIVATE_KEY
                </code>{" "}
                with a funded Base Sepolia wallet, reload, and the same button signs
                + retries.
              </div>
            </div>
          )}

          {mcpResult !== null && (
            <div className="bg-surface-2 border border-border rounded-md p-3 text-2xs font-mono text-fg-secondary max-h-56 overflow-auto mb-3">
              <pre>{JSON.stringify(mcpResult, null, 2).slice(0, 4000)}</pre>
            </div>
          )}

          {demoLog.length > 0 && (
            <div className="bg-canvas border border-border rounded-md p-3 text-2xs font-mono text-fg-tertiary max-h-40 overflow-auto">
              {demoLog.map((l, i) => (
                <div key={i}>{l}</div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {/* Recipe with language tabs */}
      <Card>
        <CardHeader
          title="Recipes"
          subtitle="drop into your agent runtime"
          right={
            <div className="flex gap-1">
              {(Object.keys(LANG_LABEL) as Lang[]).map((l) => (
                <button
                  key={l}
                  onClick={() => setLang(l)}
                  className={`px-2 py-1 rounded text-2xs uppercase tracking-wider font-mono transition-colors ${
                    lang === l
                      ? "bg-surface-3 text-fg-primary"
                      : "text-fg-tertiary hover:text-fg-secondary"
                  }`}
                >
                  {LANG_LABEL[l]}
                </button>
              ))}
            </div>
          }
        />
        <div className="p-5">
          <CodeBlock code={recipes[lang]} lang={lang} />
        </div>
      </Card>

      {/* Free synthetic dataset */}
      <Card>
        <CardHeader
          title="Synthetic dataset (free)"
          subtitle="bulk parquet · no x402 challenge"
        />
        <div className="p-5">
          <p className="text-xs text-fg-secondary mb-3 leading-relaxed">
            The synthetic + raw vulnerability slice is also exposed as a single
            Parquet file for offline training. No payment, no auth.
          </p>
          <CodeBlock
            code={`curl -O ${API_BASE}/api/synthetic/export.parquet`}
            lang="bash"
          />
        </div>
      </Card>
    </div>
  );
}
