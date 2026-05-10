# EVM Security Atlas

## Vision
A paid, agent-accessible "vulnerability landscape" platform that ingests verified contracts from Sourcify, enriches them with bug reports, hacks, audit findings, and static-analysis features, then turns that into a synthetic benchmark/training dataset focused on harmful patterns, exploit classes, and insecure design motifs.

## Core Problem
Current security knowledge is fragmented across audit PDFs, incident writeups, repos, and contest reports, while Sourcify gives a canonical anchor for exact source/metadata reconstruction.

## Key Differentiators
- Uses Sourcify as verified contract substrate for exact source-to-bytecode correspondence
- Uses Apify to collect and refresh open-web security evidence layer
- Builds normalized graph of contracts, metadata, storage layouts, vulnerabilities, incidents, and exploit patterns
- Generates synthetic, bug-focused benchmark/training dataset anchored in real verified contracts
- Exposes to humans and agents through searchable frontend plus MCP/HTTP APIs
- Gates high-value access and live enrichment with x402 payments in agent-native workflows

## Target Audiences
1. Smart-contract developers - "What vulnerabilities resemble my architecture?"
2. Auditors - "Show historical exploit classes for this protocol design."
3. Researchers - "Build benchmark subsets with ground truth."
4. Tool builders - "Benchmark my scanner/agent on real-like bugs."
5. Agents - "Need fresh exploit intelligence or contract risk profile."

## Data Model Entities
- contract_instance: chain, address, deployed bytecode hash, verification status
- compiled_contract: source bundle, compiler version, optimizer settings, EVM version, metadata hash
- source_file: normalized path, content, license, hash
- storage_layout: slots, types, inheritance, packing, upgrade-safety attributes
- vulnerability_record: class, severity, root cause, exploit preconditions, affected functions, evidence
- incident_record: hack, exploit txs, losses, date, references, affected contracts
- analysis_run: Slither results, custom heuristics, CFG/storage annotations
- synthetic_case: generated vulnerable variant, patch pair, exploit task, benchmark labels
- access_policy: public preview vs paid slices vs agent-only endpoints

## Taxonomy (Orthogonal Buckets)
- Bug class: reentrancy, access control, authz bypass, accounting error, oracle manipulation, precision/rounding, storage collision, initialization bug, upgradeability flaw, signature replay, liquidation bug, flash-loan abuse
- Layer: Solidity source, compiler/config, proxy/storage, protocol logic, integration, tokenomics/mechanics
- Exploitability: direct drain, griefing/DoS, privilege escalation, governance capture, frozen funds, dilution
- Reproducibility: report-only, static-only, PoC available, exploit reproduced, patched pair available
- Provenance: audit, incident postmortem, onchain forensic, synthetic augmentation

## Architecture Layers
| Layer | What it does | Suggested stack |
|---|---|---|
| Ingestion | Pull verified contracts, metadata, layouts, compiler settings from Sourcify; crawl audits/incidents/exploits | Sourcify API/DB mirror, Apify Actors, Python ETL, PostgreSQL |
| Normalization | Canonicalize contracts, dedupe code, map bugs to verified contracts, parse storage/AST/compiler context | Python, DuckDB, PostgreSQL, Foundry/Slither parsers |
| Analysis | Static analysis, pattern mining, synthetic sample generation, taxonomy labeling | Slither, Semgrep, Mythril/Maru, custom rules, LLM-assisted labeling |
| Dataset serving | Searchable dataset, slices, benchmark bundles, agent endpoints | FastAPI, Postgres, object storage, Parquet |
| Paid access | MCP tools and HTTP endpoints with x402-gated access | Apify MCP server + x402, custom MCP wrapper |
| Frontend | Visualize classes, timelines, compiler clusters, exploit families, contract pages | Next.js, Tailwind, Plotly/ECharts, graph views |

## Initial Milestone Scope (v1)
Build v1 around upgradeability, access control, reentrancy, accounting, and signature bugs on verified Solidity contracts.

## Implemented Components (Current State)
- Backend: FastAPI with DuckDB database, Sourcify integration, Slither analysis, x402 payment middleware
- Frontend: Basic Next.js setup
- Database schema: contracts, findings, incidents tables
- API endpoints: contract lookup, search, export (x402-gated), MCP (x402-gated)
- Ingestion pipeline: Fetches from Sourcify, runs Slither analysis, stores results

## Next Steps
1. Define ontology (vulnerability taxonomy, severity rubric, provenance model, confidence scores)
2. Build canonical Sourcify mirror (ingest verified contracts, source bundles, metadata, etc.)
3. Add external evidence ingestion (Apify for audits, disclosures, incident reports)
4. Static analysis and feature extraction (Slither/custom analyzers)
5. Human-curated seed set (high-confidence corpus from known audits/incidents)
6. Synthetic generation (transformed vulnerable variants, patch pairs, benchmark tasks)
7. Validation harness (Foundry-based exploit and patch tests)
8. Serve via API + MCP (search, filtering, benchmark export, live-enrichment tools)
9. Frontend (dashboard, contract explorer, benchmark builder, dataset release pages)
10. Governance and upgrades (review queues, confidence scoring, community submissions)