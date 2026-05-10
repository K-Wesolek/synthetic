# Plan for Milestone 1 Phase 1.1: Project Setup & Basic Infrastructure

## Goals
- Initialize project structure with backend (FastAPI) and frontend (Next.js)
- Set up DuckDB database with basic schema (contracts, findings, incidents)
- Implement Sourcify API integration for contract verification
- Add Slither static analysis for vulnerability detection
- Create basic API endpoints: contract lookup, search findings
- Implement x402 payment middleware for paid endpoints
- Set up basic Next.js frontend

## Completed Tasks (Verification)
Based on code review:

### Backend Structure ✓
- `/backend/main.py` - FastAPI app with CORS, health check, contract lookup, search, export, MCP endpoints
- `/backend/db.py` - DuckDB connection and schema initialization with contracts, findings, incidents tables
- `/backend/ingest.py` - Sourcify API integration and Slither analysis
- `/backend/query.py` - Search functionality and Parquet export
- `/backend/seed.py` - (mentioned in git log but not reviewed)
- `requirements.txt` - Dependencies including fastapi, duckdb, x402, slither, solc-select

### Frontend Structure ✓
- `/frontend/app/page.tsx` - Main page component
- `/frontend/app/layout.tsx` - Layout component
- Basic Next.js setup with Tailwind (implied by project description)

### Database Schema ✓
- Contracts table with address, chain_id, contract_name, compiler_version, etc.
- Findings table with detector, severity, confidence, description
- Incidents table with vulnerability_class, tx_hash, loss_usd, etc.
- Sequences for auto-incrementing IDs

### API Endpoints ✓
- GET `/api/health` - Health check
- GET `/api/contracts/{chain_id}/{address}` - Contract lookup with Sourcify ingestion
- GET `/api/search` - Search findings with detector, min_severity, chain_id filters
- POST `/api/export` - Export benchmark slice as Parquet (x402 gated)
- POST `/api/mcp` - MCP tool invocation (x402 gated)

### Payment Middleware ✓
- x402 configuration via environment variables
- Payment middleware registered for `/api/export` and `/api/mcp` endpoints
- Exact EVM server scheme for Base Sepolia network

### Static Analysis ✓
- Slither integration in `ingest.py`
- Solc version management via solc-select
- Analysis of Solidity sources with finding extraction

## Remaining Tasks for Phase 1.1 Completion
While the core infrastructure is in place, these items should be verified/completed:

1. **Frontend Development** - Beyond basic setup
   - [ ] Connect frontend to backend API endpoints
   - [ ] Implement contract lookup UI
   - [ ] Implement search results display
   - [ ] Add loading states and error handling

2. **Testing & Validation**
   - [ ] Create test suite for backend endpoints
   - [ ] Verify database schema creation works correctly
   - [ ] Test Sourcify integration with known verified contracts
   - [ ] Validate Slither analysis produces expected findings

3. **Documentation & Examples**
   - [ ] Update README with detailed usage instructions
   - [ ] Add example contracts for testing
   - [ ] Document API endpoints and MCP tools

4. **Configuration & Deployment**
   - [ ] Verify environment variable handling
   - [ ] Test x402 payment middleware in development mode
   - [ ] Ensure proper CORS configuration for frontend-backend communication

5. **Seed Data**
   - [ ] Review and potentially enhance seed script for initial data population
   - [ ] Verify seed script works with current database schema

## Definition of Done for Phase 1.1
- Backend API is fully functional and tested
- Frontend can successfully communicate with backend
- Contract lookup, search, and export endpoints work correctly
- Database schema is properly initialized and used
- Basic UI allows users to lookup contracts and view findings
- x402 payment middleware is configured and functional (in test mode)
- Documentation enables new users to set up and run the project

## Next Phase (1.2) Preparation
Once Phase 1.1 is complete, focus will shift to:
- Enhancing data pipeline with better deduplication and metadata handling
- Implementing external evidence ingestion via Apify
- Expanding analysis engine with custom detectors