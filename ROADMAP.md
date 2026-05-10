# Roadmap

## Milestone 1: Foundation & Core Ingestion (Phase 1.0)

### Phase 1.1: Project Setup & Basic Infrastructure
- [x] Initialize project structure with backend (FastAPI) and frontend (Next.js)
- [x] Set up DuckDB database with basic schema (contracts, findings, incidents)
- [x] Implement Sourcify API integration for contract verification
- [x] Add Slither static analysis for vulnerability detection
- [x] Create basic API endpoints: contract lookup, search findings
- [x] Implement x402 payment middleware for paid endpoints
- [x] Set up basic Next.js frontend

### Phase 1.2: Data Pipeline Enhancement
- [x] Enhance ingestion pipeline to store compiler settings, storage layout, ABI/NatSpec
- [x] Add deduplication mechanisms for contracts and source code
- [x] Implement storage layout parsing and normalization
- [x] Add metadata extraction and normalization
- [x] Create entity relationships in database schema

### Phase 1.3: External Evidence Ingestion
- [ ] Set up Apify Actors for scraping audit reports (Code4rena, Immunefi, etc.)
- [ ] Create pipeline for processing incident writeups and exploit announcements
- [ ] Implement entity matching from project names/repos/addresses to verified contracts
- [x] Add provenance tracking for all evidence sources (findings.provenance, synthetic_cases.provenance)

### Phase 1.4: Analysis Engine
- [ ] Extend static analysis with custom detectors for upgradeability, access control flaws
- [ ] Add semantic analysis for vulnerability patterns
- [ ] Implement confidence scoring for findings
- [x] Create taxonomy labeling system based on orthogonal buckets (vulnerability_class, layer, exploitability, reproducibility, provenance)

## Milestone 2: Dataset Generation & Serving (Phase 2.0)

### Phase 2.1: Synthetic Dataset Generation
- [x] Implement vulnerable variant generation from real anchored cases
- [x] Create patch pair generation functionality
- [x] Develop benchmark task creation with exploit conditions
- [ ] Add validation harness using Foundry for exploit/patch testing
- [x] Implement provenance tracking for synthetic cases

### Phase 2.2: Dataset Serving Infrastructure
- [x] Enhance export functionality to Parquet with comprehensive metadata
- [ ] Implement versioned dataset releases
- [ ] Add search indexing for efficient querying
- [x] Create benchmark bundle generation with configurable filters (`/api/synthetic/export.parquet`, filtered search export)
- [ ] Set up object storage for raw artifacts and generated samples

### Phase 2.3: API & MCP Enhancement
- [x] Expand MCP tool set with specialized vulnerability tools (`list_synthetic_cases`, `generate_synthetic`)
- [x] Add tools for synthetic dataset generation and benchmark creation
- [ ] Implement live web enrichment via Apify Actors
- [ ] Add contract comparison to known failures functionality
- [ ] Enhance access control with tiered permissions

## Milestone 3: User Experience & Agent Access (Phase 3.0)

### Phase 3.1: Frontend Development
- [x] Create security atlas dashboard with vulnerability class breakdown (recharts BarChart over `by_class`)
- [x] Implement time-series visualization of incidents by class and chain (`incident_timeline` LineChart)
- [x] Add compiler/version heatmaps and optimizer-linked bug distributions (`by_compiler` chart)
- [ ] Build storage-layout visualizer for upgradeable contracts
- [x] Develop contract page with verified source, metadata, findings, exploit lineage (Catalog + Lookup tabs)
- [ ] Implement "similar contracts / similar failures" graph
- [ ] Add static-analysis overlays on source code
- [x] Synthetic dataset browser with vulnerable+patched code panes

### Phase 3.2: Access Control & Monetization
- [ ] Implement tiered access: public indexability vs paid high-value detail
- [ ] Create transparent pricing model: pay-per-query, pay-per-Actor run, subscriptions
- [ ] Add wallet-first login for x402-native access with optional email/org accounts
- [ ] Implement provenance tracking everywhere (source type, confidence, evidence chain)
- [ ] Add clear legal boundaries: synthetic vs real cases, reproduced vs inferred patterns

### Phase 3.3: Agent-Focused Features
- [ ] Expose fine-grained MCP tools for agent consumption
- [ ] Implement REST API for batch download of datasets
- [ ] Add versioned Parquet releases for model training
- [ ] Create optional vector index over source fragments, findings, exploit descriptions
- [ ] Develop agent-to-agent flow for purchasing fresh enrichment packs

## Milestone 4: Governance & Expansion (Phase 4.0)

### Phase 4.1: Quality Assurance & Curation
- [ ] Implement review queues for community submissions
- [ ] Add confidence scoring system for all findings
- [ ] Create versioned releases with changelogs
- [ ] Implement automated validation pipelines for high-value datasets
- [ ] Add dispute resolution mechanisms for contested classifications

### Phase 4.2: Ecosystem Expansion
- [ ] Add bytecode-only mode for unverified contracts using nearest-neighbor matching
- [ ] Implement exploit simulation with local fork or Anvil replay
- [ ] Add patch recommender benchmark set
- [ ] Expand to mempool/MEV and cross-chain vulnerability analysis
- [ ] Add zk/cryptographic vulnerability tracks as later expansion

### Phase 4.3: Marketplace & Community
- [ ] Implement agent marketplace behavior for trading enrichment packs
- [ ] Add enterprise features: bulk API, private corpora, custom labels, webhooks
- [ ] Create community contribution workflow with reputation system
- [ ] Add educational resources and tutorials for security researchers
- [ ] Implement analytics dashboard for platform usage insights

## Current Status
- Phase 1.1 complete: backend API, frontend, DuckDB schema, Sourcify integration, Slither analysis, x402 middleware.
- Phase 1.2 complete: enhanced ingestion (`db_enhanced.py`/`ingest_enhanced.py`) with compiler settings, storage layout, ABI, source dedup, metadata key/value table.
- Phase 1.4 partial: PROJECT.md taxonomy (vulnerability_class, layer, exploitability, reproducibility, provenance) is now first-class on `findings` and `synthetic_cases`.
- Phase 2.1 mostly complete: rule-based synthetic generator (`backend/synthetic.py`) producing vulnerable + patched Solidity pairs with exploit precondition + benchmark task. Anchored to seed contracts via `case_uid` for idempotent reruns. Foundry validation harness still pending.
- Phase 2.2 partial: `slices/synthetic_dataset.parquet` shipped via `/api/synthetic/export.parquet`; benchmark filtering on `/api/export` with x402.
- Phase 2.3 partial: MCP tool registry extended with `list_synthetic_cases` and `generate_synthetic`.
- Phase 3.1 mostly complete: Atlas dashboard tab (severity, class, layer, compiler, incident timeline, synthetic-by-class), Catalog tab, Synthetic tab with vulnerable/patched diff view, Lookup + Findings tabs.