# EVM Security Atlas (Hackathon MVP)

Minimal vulnerability intelligence layer over verified Sourcify contracts.
Ingests verified source/metadata, enriches with static analysis, and exposes
searchable datasets via API/MCP with x402-gated access.

## Quick Start

```bash
# Backend
pip install -r requirements.txt
mkdir -p data slices
python -m backend.seed        # Pre-populate DB
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run dev
```

## Demo Flow

1. Search a verified contract by address + chain ID
2. View compiler settings, storage layout, and Slither findings
3. Filter by vulnerability class (e.g., reentrancy, access-control)
4. Export filtered findings as Parquet (x402 mock gate)

## Architecture

Sourcify API v2 -> DuckDB (contracts/findings) + Slither (analysis) -> FastAPI/MCP -> x402 gate -> Next.js UI
