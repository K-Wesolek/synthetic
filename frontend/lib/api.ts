const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ContractInfo {
  id: number;
  address: string;
  chain_id: string;
  contract_name: string | null;
  compiler_version: string | null;
  language?: string;
  optimizer_enabled: boolean | null;
  optimizer_runs: number | null;
  abi?: unknown[] | null;
  storage_layout?: Record<string, unknown> | null;
  ingested_at?: string;
  finding_count?: number;
  high_count?: number;
  medium_count?: number;
}

export interface Finding {
  finding_id?: number;
  id?: number;
  contract_id?: number;
  address?: string;
  chain_id?: string;
  contract_name?: string | null;
  detector: string;
  severity: string;
  confidence: string | null;
  description: string | null;
  first_markdown_element?: string | null;
  vulnerability_class?: string | null;
  layer?: string | null;
  exploitability?: string | null;
  reproducibility?: string | null;
  provenance?: string | null;
  confidence_score?: number | null;
}

export interface ContractSourceFile {
  id: number;
  contract_id: number;
  file_path: string;
  content: string;
  content_hash: string;
  truncated?: boolean;
}

export interface StorageSlot {
  id: number;
  contract_id: number;
  slot_number: string;
  label: string | null;
  type: string | null;
  offset: number | null;
  slot_slot: string | null;
}

export interface SimilarContract {
  id: number;
  address: string;
  chain_id: string;
  contract_name: string | null;
  compiler_version: string | null;
  shared_classes: string[];
  shared_count: number;
  similarity: number;
}

export interface ContractScore {
  score: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  classes: string[];
  top_finding: {
    id: number;
    detector: string;
    severity: string;
    score: number;
  } | null;
}

export interface ContractFull {
  contract: ContractInfo;
  score: ContractScore;
  findings: Finding[];
  sources: ContractSourceFile[];
  storage_slots: StorageSlot[];
  similar_contracts: SimilarContract[];
  related_incidents: Incident[];
}

export interface Incident {
  id: number;
  vulnerability_class: string;
  tx_hash: string | null;
  loss_usd: number | null;
  incident_date: string | null;
  source_url: string | null;
  description: string | null;
}

export interface SyntheticCase {
  id: number;
  case_uid: string;
  vulnerability_class: string;
  layer: string | null;
  exploitability: string | null;
  severity: string | null;
  title: string | null;
  description: string | null;
  exploit_precondition: string | null;
  benchmark_task: string | null;
  provenance: string | null;
  generator: string | null;
  created_at: string | null;
  anchor_address: string | null;
  anchor_name: string | null;
  anchor_chain_id: string | null;
  vulnerable_source?: string;
  patched_source?: string;
}

export interface Stats {
  totals: {
    contracts: number;
    findings: number;
    incidents: number;
    synthetic_cases: number;
    total_loss_usd: number;
  };
  severity: { severity: string; n: number }[];
  by_class: { vulnerability_class: string; n: number }[];
  by_layer: { layer: string; n: number }[];
  by_compiler: { major: string; contracts: number; findings: number }[];
  synthetic_by_class: { vulnerability_class: string; n: number }[];
  incident_timeline: {
    vulnerability_class: string;
    year: string;
    n: number;
    loss_usd: number;
  }[];
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
  if (_x402InitAttempted) return fetch;

  _x402InitAttempted = true;
  const pk = process.env.NEXT_PUBLIC_WALLET_PRIVATE_KEY;
  if (!pk) return fetch;

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
// Free endpoints
// ---------------------------------------------------------------------------

async function getJSON<T>(path: string): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`);
  if (!resp.ok) throw new Error(`${path} -> ${resp.status} ${resp.statusText}`);
  return resp.json();
}

export async function fetchContract(
  chainId: string,
  address: string
): Promise<ContractResult> {
  return getJSON<ContractResult>(`/api/contracts/${chainId}/${address}`);
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
  return getJSON<SearchResult>(`/api/search?${query}`);
}

export async function fetchStats(): Promise<Stats> {
  return getJSON<Stats>("/api/stats");
}

export interface X402Endpoint {
  id: string;
  method: string;
  path: string;
  price: string;
  mime_type: string;
  description: string;
}

export interface X402Tool {
  name: string;
  args: Record<string, string>;
  description: string;
}

export interface X402Catalog {
  network: string;
  facilitator: string;
  pay_to: string;
  dataset_version?: string;
  taxonomy_version?: string;
  endpoints: X402Endpoint[];
  tools: X402Tool[];
}

export async function fetchX402Catalog(): Promise<X402Catalog> {
  return getJSON<X402Catalog>("/api/x402/catalog");
}

export async function fetchContractFull(contractId: number): Promise<ContractFull> {
  return getJSON<ContractFull>(`/api/contracts/by-id/${contractId}/full`);
}

export async function callMcpTool(
  tool: string,
  args: Record<string, unknown> = {},
): Promise<{
  paid: boolean;
  challenge?: PaymentChallenge;
  response?: { status: number; tool: string; data: unknown };
}> {
  const fetchFn = await getPaidFetch();
  const resp = await fetchFn(`${API_BASE}/api/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool, args }),
  });

  if (resp.status === 402) {
    const raw = resp.headers.get("payment-required");
    if (raw) {
      try {
        return { paid: false, challenge: JSON.parse(atob(raw)) };
      } catch {
        /* fall through */
      }
    }
    return { paid: false, challenge: await resp.json() };
  }

  if (!resp.ok) throw new Error(`MCP failed: ${resp.status} ${resp.statusText}`);
  const data = await resp.json();
  return { paid: _paidFetch !== null, response: data };
}

export async function fetchContracts(limit = 500): Promise<{
  count: number;
  results: ContractInfo[];
}> {
  return getJSON(`/api/contracts?limit=${limit}`);
}

export async function fetchIncidents(): Promise<{
  count: number;
  results: Incident[];
}> {
  return getJSON("/api/incidents");
}

export async function fetchSynthetic(params: {
  vulnerability_class?: string;
  limit?: number;
} = {}): Promise<{ count: number; results: SyntheticCase[] }> {
  const q = new URLSearchParams();
  if (params.vulnerability_class)
    q.set("vulnerability_class", params.vulnerability_class);
  if (params.limit) q.set("limit", String(params.limit));
  return getJSON(`/api/synthetic?${q}`);
}

export async function fetchSyntheticCase(
  caseUid: string
): Promise<SyntheticCase> {
  return getJSON(`/api/synthetic/${caseUid}`);
}

export async function generateSynthetic(count: number): Promise<{
  requested: number;
  rows: number;
}> {
  const resp = await fetch(`${API_BASE}/api/synthetic/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ count }),
  });
  if (!resp.ok) throw new Error(`generate failed: ${resp.statusText}`);
  return resp.json();
}

export function syntheticParquetUrl(): string {
  return `${API_BASE}/api/synthetic/export.parquet`;
}

// ---------------------------------------------------------------------------
// Paid: benchmark Parquet export (x402-gated when running with X402 enabled)
// ---------------------------------------------------------------------------

export async function exportSlice(
  params: { detector?: string; min_severity?: string }
): Promise<{ blob?: Blob; challenge?: PaymentChallenge; paid?: boolean }> {
  const fetchFn = await getPaidFetch();

  const resp = await fetchFn(`${API_BASE}/api/export`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });

  if (resp.status === 402) {
    const raw = resp.headers.get("payment-required");
    if (raw) {
      try {
        return { challenge: JSON.parse(atob(raw)) };
      } catch {
        /* fall through */
      }
    }
    return { challenge: await resp.json() };
  }

  if (!resp.ok) throw new Error(`Export failed: ${resp.statusText}`);
  return { blob: await resp.blob(), paid: _paidFetch !== null };
}

// ---------------------------------------------------------------------------
// Explorer: TF-IDF + UMAP embedding index over contracts/synthetic/incidents
// ---------------------------------------------------------------------------

export type AtlasSourceType = "contract" | "synthetic" | "incident";

export interface AtlasPoint {
  source_type: AtlasSourceType;
  source_id: number;
  label: string;
  x: number | null;
  y: number | null;
  cluster: number | null;
  novelty: number | null;
  meta: Record<string, unknown>;
}

export interface SimilarHit extends AtlasPoint {
  similarity: number;
}

export interface IncidentRecord {
  id: number;
  name: string | null;
  vulnerability_class: string | null;
  layer: string | null;
  exploitability: string | null;
  chain: string | null;
  tx_hash: string | null;
  loss_usd: number | null;
  incident_date: string | null;
  source_url: string | null;
  description: string | null;
  confidence: string | null;
  original_classification: string | null;
  original_technique: string | null;
  provenance: string | null;
}

export interface IncidentFull {
  incident: IncidentRecord;
  similar: SimilarHit[];
}

export interface ClusterSummary {
  cluster: number;
  size: number;
  by_type: Record<string, number>;
  dominant_class: string | null;
  class_distribution: Record<string, number>;
  total_loss_usd: number;
  mean_novelty: number | null;
  sample_labels: string[];
}

export interface AtRiskRow {
  contract_id: number;
  address: string;
  chain_id: string;
  contract_name: string | null;
  risk_score: number;
  neighbour_count: number;
  dominant_class: string | null;
  top_match: {
    incident_id: number;
    name: string;
    similarity: number;
    vulnerability_class: string | null;
    loss_usd: number | null;
  };
}

export interface TimelinePoint {
  bucket: string;
  n: number;
  loss_usd: number;
  vulnerability_class: string | null;
}

export async function listIncidents(params: {
  vulnerability_class?: string;
  chain?: string;
  min_loss?: number;
  order?: "date_desc" | "date_asc" | "loss_desc" | "loss_asc";
  limit?: number;
} = {}): Promise<{ count: number; results: IncidentRecord[] }> {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  });
  const r = await fetch(`${API_BASE}/api/incidents?${q.toString()}`);
  if (!r.ok) throw new Error(`incidents fetch failed: ${r.status}`);
  return r.json();
}

export async function getIncidentFull(id: number): Promise<IncidentFull> {
  const r = await fetch(`${API_BASE}/api/incidents/${id}/full`);
  if (!r.ok) throw new Error(`incident ${id} fetch failed: ${r.status}`);
  return r.json();
}

export async function getProjection(
  types?: AtlasSourceType[],
  limit = 5000
): Promise<{ results: AtlasPoint[] }> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (types && types.length) q.set("types", types.join(","));
  const r = await fetch(`${API_BASE}/api/explore/projection?${q.toString()}`);
  if (!r.ok) throw new Error(`projection failed: ${r.status}`);
  return r.json();
}

export async function getSimilar(
  source_type: AtlasSourceType,
  source_id: number,
  k = 12,
  same_type_only = false
): Promise<{ results: SimilarHit[]; count: number }> {
  const q = new URLSearchParams({
    source_type,
    source_id: String(source_id),
    k: String(k),
    same_type_only: String(same_type_only),
  });
  const r = await fetch(`${API_BASE}/api/explore/similar?${q.toString()}`);
  if (!r.ok) throw new Error(`similar failed: ${r.status}`);
  return r.json();
}

export async function getTopNovel(
  source_type?: AtlasSourceType,
  k = 25
): Promise<{ results: AtlasPoint[] }> {
  const q = new URLSearchParams({ k: String(k) });
  if (source_type) q.set("source_type", source_type);
  const r = await fetch(`${API_BASE}/api/explore/novel?${q.toString()}`);
  if (!r.ok) throw new Error(`novel failed: ${r.status}`);
  return r.json();
}

export async function getClusters(): Promise<{ clusters: ClusterSummary[] }> {
  const r = await fetch(`${API_BASE}/api/explore/clusters`);
  if (!r.ok) throw new Error(`clusters failed: ${r.status}`);
  return r.json();
}

export async function getAtRiskWatchlist(
  k = 20,
  min_score = 0.3
): Promise<{ count: number; results: AtRiskRow[] }> {
  const q = new URLSearchParams({ k: String(k), min_score: String(min_score) });
  const r = await fetch(`${API_BASE}/api/explore/at-risk-watchlist?${q.toString()}`);
  if (!r.ok) throw new Error(`at-risk failed: ${r.status}`);
  return r.json();
}

export async function getRiskScore(contract_id: number, k = 10): Promise<{
  contract_id: number;
  score: number;
  neighbour_count: number;
  class_distribution: Record<string, number>;
  neighbours: Array<{
    incident_id: number;
    name: string;
    similarity: number;
    vulnerability_class: string | null;
    loss_usd: number | null;
    incident_date: string | null;
  }>;
}> {
  const q = new URLSearchParams({ contract_id: String(contract_id), k: String(k) });
  const r = await fetch(`${API_BASE}/api/explore/risk-score?${q.toString()}`);
  if (!r.ok) throw new Error(`risk-score failed: ${r.status}`);
  return r.json();
}

export async function getUnhackedSiblings(
  incident_id: number,
  k = 15
): Promise<{ incident_id: number; count: number; results: SimilarHit[] }> {
  const q = new URLSearchParams({ incident_id: String(incident_id), k: String(k) });
  const r = await fetch(`${API_BASE}/api/explore/find-unhacked-siblings?${q.toString()}`);
  if (!r.ok) throw new Error(`unhacked-siblings failed: ${r.status}`);
  return r.json();
}

export async function getTimeline(
  granularity: "month" | "quarter" | "year" = "month"
): Promise<{ granularity: string; results: TimelinePoint[] }> {
  const r = await fetch(`${API_BASE}/api/timeline?granularity=${granularity}`);
  if (!r.ok) throw new Error(`timeline failed: ${r.status}`);
  return r.json();
}
