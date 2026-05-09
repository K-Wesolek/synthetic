const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ContractInfo {
  id: number;
  address: string;
  chain_id: string;
  contract_name: string | null;
  compiler_version: string | null;
  language: string;
  optimizer_enabled: boolean | null;
  optimizer_runs: number | null;
  abi: unknown[] | null;
  storage_layout: Record<string, unknown> | null;
}

export interface Finding {
  finding_id: number;
  address: string;
  chain_id: string;
  contract_name: string | null;
  detector: string;
  severity: string;
  confidence: string | null;
  description: string | null;
}

export interface ContractResult {
  contract: ContractInfo;
  findings: Finding[];
}

export interface SearchResult {
  count: number;
  results: Finding[];
}

export interface PaymentChallenge {
  scheme: string;
  network: string;
  payTo: string;
  maxAmountRequired: string;
  description?: string;
}

// ---------------------------------------------------------------------------
// x402 client – auto-signs and retries on 402 if a wallet key is configured
// ---------------------------------------------------------------------------

let _paidFetch: typeof fetch | null = null;
let _x402InitAttempted = false;

async function getPaidFetch(): Promise<typeof fetch> {
  if (_paidFetch) return _paidFetch;
  if (_x402InitAttempted) return fetch; // already tried, no key

  _x402InitAttempted = true;
  const pk = process.env.NEXT_PUBLIC_WALLET_PRIVATE_KEY;
  if (!pk) return fetch; // no wallet configured – fall back to plain fetch

  try {
    const { x402Client } = await import("@x402/core/client");
    const { ExactEvmScheme } = await import("@x402/evm/exact/client");
    const { wrapFetchWithPayment } = await import("@x402/fetch");
    const { privateKeyToAccount } = await import("viem/accounts");

    const signer = privateKeyToAccount(pk as `0x${string}`);
    const client = new x402Client();
    client.register("eip155:*", new ExactEvmScheme(signer));
    _paidFetch = wrapFetchWithPayment(fetch, client);
    return _paidFetch;
  } catch {
    console.warn("x402 client init failed – falling back to plain fetch");
    return fetch;
  }
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export async function fetchContract(
  chainId: string,
  address: string
): Promise<ContractResult> {
  const resp = await fetch(`${API_BASE}/api/contracts/${chainId}/${address}`);
  if (!resp.ok) throw new Error(`Failed to fetch contract: ${resp.statusText}`);
  return resp.json();
}

export async function searchFindings(params: {
  detector?: string;
  min_severity?: string;
  chain_id?: string;
}): Promise<SearchResult> {
  const query = new URLSearchParams();
  if (params.detector) query.set("detector", params.detector);
  if (params.min_severity) query.set("min_severity", params.min_severity);
  if (params.chain_id) query.set("chain_id", params.chain_id);
  const resp = await fetch(`${API_BASE}/api/search?${query}`);
  if (!resp.ok) throw new Error(`Search failed: ${resp.statusText}`);
  return resp.json();
}

/**
 * Export a benchmark slice as Parquet.
 *
 * If NEXT_PUBLIC_WALLET_PRIVATE_KEY is set, the x402 SDK automatically signs
 * and pays on 402. Otherwise the raw 402 challenge is returned so the UI can
 * display it.
 */
export async function exportSlice(
  params: { detector?: string; min_severity?: string },
): Promise<{ blob?: Blob; challenge?: PaymentChallenge; paid?: boolean }> {
  const fetchFn = await getPaidFetch();

  const resp = await fetchFn(`${API_BASE}/api/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });

  if (resp.status === 402) {
    // No wallet configured or payment failed – surface challenge to UI
    const raw = resp.headers.get("payment-required");
    if (raw) {
      try {
        return { challenge: JSON.parse(atob(raw)) };
      } catch { /* fall through */ }
    }
    return { challenge: await resp.json() };
  }

  if (!resp.ok) throw new Error(`Export failed: ${resp.statusText}`);
  return { blob: await resp.blob(), paid: _paidFetch !== null };
}
