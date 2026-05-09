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
  payment_required: string;
  wallet: string;
  network: string;
  message: string;
}

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

export async function exportSlice(
  params: { detector?: string; min_severity?: string },
  paymentSig?: string
): Promise<{ blob?: Blob; challenge?: PaymentChallenge }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (paymentSig) headers["X-Payment-Signed"] = paymentSig;

  const resp = await fetch(`${API_BASE}/api/export`, {
    method: "POST",
    headers,
    body: JSON.stringify(params),
  });

  if (resp.status === 402) {
    return { challenge: await resp.json() };
  }
  if (!resp.ok) throw new Error(`Export failed: ${resp.statusText}`);
  return { blob: await resp.blob() };
}
