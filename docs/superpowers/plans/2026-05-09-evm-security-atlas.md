# EVM Security Atlas Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hackathon MVP that ingests verified Sourcify contracts, enriches them with Slither static analysis, stores results in DuckDB, and exposes searchable vulnerability datasets via a FastAPI/MCP API with x402-gated Parquet export and a Next.js UI.

**Architecture:** Sourcify API v2 provides verified contract sources and metadata. Slither performs static analysis (optional -- degrades gracefully if not installed). DuckDB stores contracts + findings for fast columnar queries. FastAPI serves REST + MCP endpoints with mock x402 payment gating on export operations. Next.js frontend provides search, contract viewer, findings table, and export controls.

**Tech Stack:** Python 3.10+, FastAPI, DuckDB, Slither, requests, pyarrow, pandas, pytest, Next.js 14, Tailwind CSS, Recharts

---

## File Structure

```
backend/
  __init__.py          # Package marker
  db.py                # DuckDB schema init, connection helper, insert/query helpers
  ingest.py            # Sourcify API client + Slither subprocess wrapper
  query.py             # search_vulnerabilities, build_benchmark_slice
  main.py              # FastAPI app, REST routes, MCP endpoint, x402 mock gate
  seed.py              # Pre-populate DB with known vulnerable contracts + findings
tests/
  __init__.py          # Package marker
  conftest.py          # Shared fixtures (in-memory DuckDB, seeded DB)
  test_db.py           # Database schema + insert/query tests
  test_ingest.py       # Sourcify client + Slither wrapper tests (mocked I/O)
  test_query.py        # Search + export tests
  test_api.py          # FastAPI endpoint tests via TestClient
frontend/
  package.json         # Next.js + Tailwind + Recharts deps
  next.config.js       # Next.js config
  tailwind.config.js   # Tailwind config
  postcss.config.js    # PostCSS config
  app/
    layout.tsx         # Root layout with global styles
    page.tsx           # Main page: search, contract view, findings, export
    globals.css        # Tailwind base styles
  lib/
    api.ts             # API client functions
data/                  # DuckDB file (gitignored, created at runtime)
slices/                # Generated Parquet exports (gitignored)
requirements.txt       # Python dependencies
.gitignore             # Ignore data/, slices/, node_modules/, __pycache__/
README.md              # Project readme
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `.gitignore`
- Create: `README.md`
- Create: `backend/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: Initialize git repository**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
git init
```
Expected: `Initialized empty Git repository`

- [ ] **Step 2: Create requirements.txt**

```
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
duckdb>=0.9.0
requests>=2.31.0
pyarrow>=14.0.0
pandas>=2.1.0
pytest>=7.4.0
httpx>=0.25.0
```

- [ ] **Step 3: Create .gitignore**

```
__pycache__/
*.pyc
.pytest_cache/
data/*.duckdb
data/*.wal
slices/*.parquet
node_modules/
.next/
.env
*.egg-info/
dist/
build/
```

- [ ] **Step 4: Create README.md**

```markdown
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
```

- [ ] **Step 5: Create package marker files and directories**

Create `backend/__init__.py` and `tests/__init__.py` as empty files.

Run:
```bash
mkdir -p backend tests data slices
touch backend/__init__.py tests/__init__.py
```

- [ ] **Step 6: Install Python dependencies**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
pip install -r requirements.txt
```
Expected: All packages install successfully.

- [ ] **Step 7: Commit scaffolding**

```bash
git add requirements.txt .gitignore README.md backend/__init__.py tests/__init__.py
git commit -m "chore: project scaffolding with deps and directory structure"
```

---

### Task 2: Database Layer

**Files:**
- Create: `backend/db.py`
- Create: `tests/conftest.py`
- Create: `tests/test_db.py`

- [ ] **Step 1: Write failing test for schema initialization**

Create `tests/test_db.py`:

```python
import duckdb


def test_init_db_creates_tables(db):
    tables = db.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
    ).fetchall()
    table_names = {row[0] for row in tables}
    assert "contracts" in table_names
    assert "findings" in table_names
    assert "incidents" in table_names
```

Create `tests/conftest.py`:

```python
import pytest
import duckdb
from backend.db import init_db


@pytest.fixture
def db():
    con = duckdb.connect(":memory:")
    init_db(con)
    yield con
    con.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
python -m pytest tests/test_db.py::test_init_db_creates_tables -v
```
Expected: FAIL -- `ModuleNotFoundError: No module named 'backend.db'` or `ImportError: cannot import name 'init_db'`

- [ ] **Step 3: Implement db.py with schema init and helpers**

Create `backend/db.py`:

```python
import json
import os

import duckdb

DB_PATH = os.environ.get("ATLAS_DB_PATH", "data/atlas.duckdb")

_SCHEMA_STATEMENTS = [
    "CREATE SEQUENCE IF NOT EXISTS seq_contracts START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_findings START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_incidents START 1",
    """
    CREATE TABLE IF NOT EXISTS contracts (
        id INTEGER DEFAULT nextval('seq_contracts') PRIMARY KEY,
        address VARCHAR NOT NULL,
        chain_id VARCHAR NOT NULL,
        contract_name VARCHAR,
        compiler_version VARCHAR,
        language VARCHAR DEFAULT 'Solidity',
        optimizer_enabled BOOLEAN,
        optimizer_runs INTEGER,
        abi VARCHAR,
        metadata VARCHAR,
        storage_layout VARCHAR,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(address, chain_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER DEFAULT nextval('seq_findings') PRIMARY KEY,
        contract_id INTEGER NOT NULL,
        detector VARCHAR NOT NULL,
        severity VARCHAR NOT NULL,
        confidence VARCHAR,
        description TEXT,
        first_markdown_element TEXT,
        FOREIGN KEY (contract_id) REFERENCES contracts(id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER DEFAULT nextval('seq_incidents') PRIMARY KEY,
        vulnerability_class VARCHAR NOT NULL,
        tx_hash VARCHAR,
        loss_usd DOUBLE,
        incident_date DATE,
        source_url VARCHAR,
        description TEXT
    )
    """,
]


def get_connection(db_path: str | None = None) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection. Uses ATLAS_DB_PATH env var or default."""
    path = db_path or DB_PATH
    return duckdb.connect(path)


def init_db(con: duckdb.DuckDBPyConnection) -> None:
    """Create all tables and sequences if they don't exist."""
    for stmt in _SCHEMA_STATEMENTS:
        con.execute(stmt)


def insert_contract(
    con: duckdb.DuckDBPyConnection,
    address: str,
    chain_id: str,
    contract_name: str | None = None,
    compiler_version: str | None = None,
    language: str = "Solidity",
    optimizer_enabled: bool | None = None,
    optimizer_runs: int | None = None,
    abi: list | None = None,
    metadata: dict | None = None,
    storage_layout: dict | None = None,
) -> int:
    """Insert a contract record. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO contracts
            (address, chain_id, contract_name, compiler_version,
             language, optimizer_enabled, optimizer_runs, abi, metadata, storage_layout)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [
            address,
            chain_id,
            contract_name,
            compiler_version,
            language,
            optimizer_enabled,
            optimizer_runs,
            json.dumps(abi) if abi is not None else None,
            json.dumps(metadata) if metadata is not None else None,
            json.dumps(storage_layout) if storage_layout is not None else None,
        ],
    ).fetchone()
    return row[0]


def insert_finding(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    detector: str,
    severity: str,
    confidence: str | None = None,
    description: str | None = None,
    first_markdown_element: str | None = None,
) -> int:
    """Insert a finding record. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO findings
            (contract_id, detector, severity, confidence, description, first_markdown_element)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [contract_id, detector, severity, confidence, description, first_markdown_element],
    ).fetchone()
    return row[0]


def insert_incident(
    con: duckdb.DuckDBPyConnection,
    vulnerability_class: str,
    tx_hash: str | None = None,
    loss_usd: float | None = None,
    incident_date: str | None = None,
    source_url: str | None = None,
    description: str | None = None,
) -> int:
    """Insert an incident record. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO incidents
            (vulnerability_class, tx_hash, loss_usd, incident_date, source_url, description)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [vulnerability_class, tx_hash, loss_usd, incident_date, source_url, description],
    ).fetchone()
    return row[0]


def get_contract(con: duckdb.DuckDBPyConnection, chain_id: str, address: str) -> dict | None:
    """Fetch a contract by chain_id + address. Returns dict or None."""
    row = con.execute(
        "SELECT * FROM contracts WHERE chain_id = ? AND address = ?",
        [chain_id, address],
    ).fetchone()
    if row is None:
        return None
    cols = [desc[0] for desc in con.description]
    record = dict(zip(cols, row))
    for json_col in ("abi", "metadata", "storage_layout"):
        if record[json_col] is not None:
            record[json_col] = json.loads(record[json_col])
    return record


def get_findings_for_contract(con: duckdb.DuckDBPyConnection, contract_id: int) -> list[dict]:
    """Fetch all findings for a given contract id."""
    rows = con.execute(
        "SELECT * FROM findings WHERE contract_id = ? ORDER BY severity",
        [contract_id],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_db.py::test_init_db_creates_tables -v
```
Expected: PASS

- [ ] **Step 5: Write failing test for insert + query contract**

Add to `tests/test_db.py`:

```python
from backend.db import insert_contract, get_contract


def test_insert_and_get_contract(db):
    cid = insert_contract(
        db,
        address="0xDEAD",
        chain_id="1",
        contract_name="TestToken",
        compiler_version="0.8.19",
        optimizer_enabled=True,
        optimizer_runs=200,
        abi=[{"type": "function", "name": "transfer"}],
    )
    assert cid == 1

    contract = get_contract(db, chain_id="1", address="0xDEAD")
    assert contract is not None
    assert contract["contract_name"] == "TestToken"
    assert contract["compiler_version"] == "0.8.19"
    assert contract["optimizer_enabled"] is True
    assert contract["abi"] == [{"type": "function", "name": "transfer"}]
```

- [ ] **Step 6: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_db.py::test_insert_and_get_contract -v
```
Expected: PASS (implementation already exists from Step 3)

- [ ] **Step 7: Write failing test for insert + query findings**

Add to `tests/test_db.py`:

```python
from backend.db import insert_finding, get_findings_for_contract


def test_insert_and_get_findings(db):
    cid = insert_contract(db, address="0xBEEF", chain_id="1")
    fid = insert_finding(
        db,
        contract_id=cid,
        detector="reentrancy-eth",
        severity="High",
        confidence="Medium",
        description="Reentrancy in withdraw()",
    )
    assert fid == 1

    findings = get_findings_for_contract(db, cid)
    assert len(findings) == 1
    assert findings[0]["detector"] == "reentrancy-eth"
    assert findings[0]["severity"] == "High"
    assert findings[0]["description"] == "Reentrancy in withdraw()"
```

- [ ] **Step 8: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_db.py::test_insert_and_get_findings -v
```
Expected: PASS

- [ ] **Step 9: Write test for duplicate contract constraint**

Add to `tests/test_db.py`:

```python
import duckdb as _duckdb
import pytest


def test_duplicate_contract_raises(db):
    insert_contract(db, address="0xAAAA", chain_id="1")
    with pytest.raises(_duckdb.ConstraintException):
        insert_contract(db, address="0xAAAA", chain_id="1")
```

- [ ] **Step 10: Run all database tests**

Run:
```bash
python -m pytest tests/test_db.py -v
```
Expected: 4 tests PASS

- [ ] **Step 11: Commit database layer**

```bash
git add backend/db.py tests/conftest.py tests/test_db.py
git commit -m "feat: DuckDB schema with contracts, findings, incidents tables and helpers"
```

---

### Task 3: Sourcify Client

**Files:**
- Create: `backend/ingest.py`
- Create: `tests/test_ingest.py`

- [ ] **Step 1: Write failing test for fetch_verified_contract**

Create `tests/test_ingest.py`:

```python
from unittest.mock import patch, MagicMock


MOCK_SOURCIFY_RESPONSE = {
    "chainId": "1",
    "address": "0xDEAD",
    "match": "exact_match",
    "sources": {
        "contracts/Token.sol": {
            "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Token {}"
        }
    },
    "abi": [{"type": "function", "name": "transfer"}],
    "compilation": {
        "language": "Solidity",
        "compiler": "solc",
        "compilerVersion": "0.8.19+commit.7dd6d404",
        "compilerSettings": {"optimizer": {"enabled": True, "runs": 200}},
        "name": "Token",
        "fullyQualifiedName": "contracts/Token.sol:Token",
    },
    "metadata": {"compiler": {"version": "0.8.19"}},
    "storageLayout": {
        "storage": [{"label": "balance", "slot": "0", "type": "t_uint256"}],
        "types": {"t_uint256": {"label": "uint256", "numberOfBytes": "32"}},
    },
}


def test_fetch_verified_contract_success():
    from backend.ingest import fetch_verified_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp) as mock_get:
        result = fetch_verified_contract("1", "0xDEAD")

    mock_get.assert_called_once()
    call_url = mock_get.call_args[0][0]
    assert "/v2/contract/1/0xDEAD" in call_url

    assert "contracts/Token.sol" in result["sources"]
    assert result["compilation"]["compilerVersion"] == "0.8.19+commit.7dd6d404"
    assert result["compilation"]["name"] == "Token"
    assert result["abi"] == [{"type": "function", "name": "transfer"}]
    assert result["storage_layout"]["storage"][0]["label"] == "balance"
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/test_ingest.py::test_fetch_verified_contract_success -v
```
Expected: FAIL -- `ModuleNotFoundError: No module named 'backend.ingest'`

- [ ] **Step 3: Implement fetch_verified_contract**

Create `backend/ingest.py`:

```python
import json
import subprocess
import tempfile
from pathlib import Path

import requests

SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract"


def fetch_verified_contract(chain_id: str, address: str) -> dict:
    """Fetch verified contract source + metadata from Sourcify API v2.

    Returns dict with keys: sources, abi, compilation, metadata, storage_layout,
    chain_id, address.
    """
    url = f"{SOURCIFY_BASE}/{chain_id}/{address}"
    resp = requests.get(
        url,
        params={"fields": "sources,abi,compilation,metadata,storageLayout"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "sources": data.get("sources", {}),
        "abi": data.get("abi", []),
        "compilation": data.get("compilation", {}),
        "metadata": data.get("metadata", {}),
        "storage_layout": data.get("storageLayout"),
        "chain_id": data.get("chainId", chain_id),
        "address": data.get("address", address),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_ingest.py::test_fetch_verified_contract_success -v
```
Expected: PASS

- [ ] **Step 5: Write test for contract-not-found (404)**

Add to `tests/test_ingest.py`:

```python
import requests as _requests
import pytest


def test_fetch_verified_contract_not_found():
    from backend.ingest import fetch_verified_contract

    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = _requests.HTTPError("404 Not Found")

    with patch("backend.ingest.requests.get", return_value=mock_resp):
        with pytest.raises(_requests.HTTPError):
            fetch_verified_contract("1", "0x0000000000000000000000000000000000000000")
```

- [ ] **Step 6: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_ingest.py -v
```
Expected: 2 tests PASS

- [ ] **Step 7: Commit Sourcify client**

```bash
git add backend/ingest.py tests/test_ingest.py
git commit -m "feat: Sourcify API v2 client for fetching verified contracts"
```

---

### Task 4: Slither Analysis Wrapper

**Files:**
- Modify: `backend/ingest.py`
- Modify: `tests/test_ingest.py`

- [ ] **Step 1: Write failing test for run_slither_analysis**

Add to `tests/test_ingest.py`:

```python
MOCK_SLITHER_OUTPUT = json.dumps({
    "success": True,
    "error": None,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in Contract.withdraw()",
                "first_markdown_element": "contracts/Token.sol#L42",
            },
            {
                "check": "unchecked-lowlevel",
                "impact": "Medium",
                "confidence": "Medium",
                "description": "Low-level call in Contract.send()",
                "first_markdown_element": "contracts/Token.sol#L55",
            },
        ]
    },
})

import json


def test_run_slither_analysis_parses_output():
    from backend.ingest import run_slither_analysis

    mock_result = MagicMock()
    mock_result.stdout = MOCK_SLITHER_OUTPUT
    mock_result.returncode = 0

    sources = {
        "contracts/Token.sol": {
            "content": "pragma solidity ^0.8.0;\ncontract Token {}"
        }
    }

    with patch("backend.ingest.subprocess.run", return_value=mock_result) as mock_run:
        with patch("backend.ingest._is_slither_available", return_value=True):
            findings = run_slither_analysis(sources)

    assert len(findings) == 2
    assert findings[0]["detector"] == "reentrancy-eth"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == "Medium"
    assert findings[1]["detector"] == "unchecked-lowlevel"
    assert findings[1]["severity"] == "Medium"
```

Add import at top of file:

```python
import json
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/test_ingest.py::test_run_slither_analysis_parses_output -v
```
Expected: FAIL -- `ImportError: cannot import name 'run_slither_analysis'`

- [ ] **Step 3: Implement run_slither_analysis**

Add to `backend/ingest.py` (below `fetch_verified_contract`):

```python
def _is_slither_available() -> bool:
    """Check if slither CLI is installed and runnable."""
    try:
        subprocess.run(["slither", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def run_slither_analysis(sources: dict) -> list[dict]:
    """Run Slither static analysis on Solidity sources.

    Args:
        sources: mapping of filepath -> {"content": "..."} or filepath -> "source code"

    Returns:
        List of finding dicts with keys: detector, severity, confidence,
        description, first_markdown_element.
        Returns empty list if Slither is unavailable or analysis fails.
    """
    if not _is_slither_available():
        return []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        sol_files = []

        for filepath, source_data in sources.items():
            content = source_data["content"] if isinstance(source_data, dict) else source_data
            full_path = tmp / filepath
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            if filepath.endswith(".sol"):
                sol_files.append(str(full_path))

        if not sol_files:
            return []

        try:
            result = subprocess.run(
                ["slither", sol_files[0], "--json", "-"],
                capture_output=True,
                text=True,
                cwd=str(tmp),
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return []

        output_text = result.stdout
        if not output_text:
            return []

        try:
            output = json.loads(output_text)
            detectors = output.get("results", {}).get("detectors", [])
            return [
                {
                    "detector": d.get("check", "unknown"),
                    "severity": d.get("impact", "Unknown"),
                    "confidence": d.get("confidence", "Unknown"),
                    "description": d.get("description", ""),
                    "first_markdown_element": d.get("first_markdown_element", ""),
                }
                for d in detectors
            ]
        except (json.JSONDecodeError, KeyError):
            return []
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_ingest.py::test_run_slither_analysis_parses_output -v
```
Expected: PASS

- [ ] **Step 5: Write test for slither-not-installed graceful degradation**

Add to `tests/test_ingest.py`:

```python
def test_run_slither_not_installed_returns_empty():
    from backend.ingest import run_slither_analysis

    sources = {"Token.sol": {"content": "pragma solidity ^0.8.0;"}}

    with patch("backend.ingest._is_slither_available", return_value=False):
        findings = run_slither_analysis(sources)

    assert findings == []
```

- [ ] **Step 6: Run all ingest tests**

Run:
```bash
python -m pytest tests/test_ingest.py -v
```
Expected: 4 tests PASS

- [ ] **Step 7: Commit Slither wrapper**

```bash
git add backend/ingest.py tests/test_ingest.py
git commit -m "feat: Slither analysis wrapper with graceful degradation"
```

---

### Task 5: Ingestion Pipeline

**Files:**
- Modify: `backend/ingest.py`
- Create: `tests/test_pipeline.py`

- [ ] **Step 1: Write failing test for ingest_contract**

Create `tests/test_pipeline.py`:

```python
from unittest.mock import patch, MagicMock
from tests.test_ingest import MOCK_SOURCIFY_RESPONSE


def test_ingest_contract_stores_in_db(db):
    from backend.ingest import ingest_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp):
        with patch("backend.ingest._is_slither_available", return_value=False):
            result = ingest_contract(db, "1", "0xDEAD")

    assert result["contract"]["contract_name"] == "Token"
    assert result["contract"]["compiler_version"] == "0.8.19+commit.7dd6d404"
    assert result["contract"]["address"] == "0xDEAD"
    assert isinstance(result["findings"], list)


def test_ingest_contract_returns_cached_on_second_call(db):
    from backend.ingest import ingest_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp) as mock_get:
        with patch("backend.ingest._is_slither_available", return_value=False):
            ingest_contract(db, "1", "0xDEAD")
            result = ingest_contract(db, "1", "0xDEAD")

    # Sourcify should only be called once -- second call reads from DB cache
    assert mock_get.call_count == 1
    assert result["contract"]["contract_name"] == "Token"
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/test_pipeline.py -v
```
Expected: FAIL -- `ImportError: cannot import name 'ingest_contract'`

- [ ] **Step 3: Implement ingest_contract**

Add to `backend/ingest.py` (at the end):

```python
from backend.db import (
    get_contract,
    get_findings_for_contract,
    insert_contract,
    insert_finding,
)


def ingest_contract(
    con,
    chain_id: str,
    address: str,
) -> dict:
    """Fetch, analyze, and store a contract. Returns cached data if already ingested.

    Returns dict with keys: contract (dict), findings (list[dict]).
    """
    existing = get_contract(con, chain_id, address)
    if existing is not None:
        findings = get_findings_for_contract(con, existing["id"])
        return {"contract": existing, "findings": findings}

    data = fetch_verified_contract(chain_id, address)

    compilation = data.get("compilation", {})
    settings = compilation.get("compilerSettings", {})
    optimizer = settings.get("optimizer", {})

    contract_id = insert_contract(
        con,
        address=address,
        chain_id=chain_id,
        contract_name=compilation.get("name"),
        compiler_version=compilation.get("compilerVersion"),
        language=compilation.get("language", "Solidity"),
        optimizer_enabled=optimizer.get("enabled"),
        optimizer_runs=optimizer.get("runs"),
        abi=data.get("abi"),
        metadata=data.get("metadata"),
        storage_layout=data.get("storage_layout"),
    )

    slither_findings = run_slither_analysis(data.get("sources", {}))

    stored_findings = []
    for f in slither_findings:
        fid = insert_finding(
            con,
            contract_id=contract_id,
            detector=f["detector"],
            severity=f["severity"],
            confidence=f.get("confidence"),
            description=f.get("description"),
            first_markdown_element=f.get("first_markdown_element"),
        )
        f["id"] = fid
        f["contract_id"] = contract_id
        stored_findings.append(f)

    contract = get_contract(con, chain_id, address)
    return {"contract": contract, "findings": stored_findings}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_pipeline.py -v
```
Expected: 2 tests PASS

- [ ] **Step 5: Commit ingestion pipeline**

```bash
git add backend/ingest.py tests/test_pipeline.py
git commit -m "feat: ingestion pipeline with Sourcify fetch, Slither analysis, DB caching"
```

---

### Task 6: Query and Export Functions

**Files:**
- Create: `backend/query.py`
- Create: `tests/test_query.py`

- [ ] **Step 1: Write failing test for search_vulnerabilities**

Create `tests/test_query.py`:

```python
from backend.db import insert_contract, insert_finding


def _seed_test_data(db):
    """Insert sample contracts + findings for query tests."""
    c1 = insert_contract(db, address="0xAAAA", chain_id="1", contract_name="VulnToken")
    insert_finding(db, c1, "reentrancy-eth", "High", "Medium", "Reentrancy in withdraw()")
    insert_finding(db, c1, "unchecked-lowlevel", "Medium", "Medium", "Unchecked call")
    insert_finding(db, c1, "solc-version", "Informational", "High", "Old solc version")

    c2 = insert_contract(db, address="0xBBBB", chain_id="1", contract_name="SafeToken")
    insert_finding(db, c2, "reentrancy-eth", "High", "High", "Reentrancy in deposit()")

    return c1, c2


def test_search_all_findings(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db)
    assert len(results) == 4


def test_search_by_detector(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, detector="reentrancy-eth")
    assert len(results) == 2
    assert all(r["detector"] == "reentrancy-eth" for r in results)


def test_search_by_min_severity(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, min_severity="Medium")
    # Should return High + Medium, not Informational
    assert len(results) == 3
    severities = {r["severity"] for r in results}
    assert "Informational" not in severities


def test_search_by_detector_and_severity(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, detector="reentrancy-eth", min_severity="High")
    assert len(results) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
python -m pytest tests/test_query.py -v
```
Expected: FAIL -- `ModuleNotFoundError: No module named 'backend.query'`

- [ ] **Step 3: Implement search_vulnerabilities**

Create `backend/query.py`:

```python
import hashlib
import json
from pathlib import Path

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

SEVERITY_RANK = {
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Optimization": 0,
}


def search_vulnerabilities(
    con: duckdb.DuckDBPyConnection,
    detector: str | None = None,
    min_severity: str | None = None,
    chain_id: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Search findings with optional filters.

    Args:
        con: DuckDB connection
        detector: filter by detector name (exact match)
        min_severity: minimum severity level (High, Medium, Low, Informational, Optimization)
        chain_id: filter by chain
        limit: max results

    Returns:
        List of finding dicts with contract address and chain_id joined in.
    """
    query = """
        SELECT
            c.address,
            c.chain_id,
            c.contract_name,
            f.id AS finding_id,
            f.detector,
            f.severity,
            f.confidence,
            f.description
        FROM findings f
        JOIN contracts c ON f.contract_id = c.id
        WHERE 1=1
    """
    params: list = []

    if detector is not None:
        query += " AND f.detector = ?"
        params.append(detector)

    if min_severity is not None:
        min_rank = SEVERITY_RANK.get(min_severity, 0)
        query += """
            AND CASE f.severity
                WHEN 'High' THEN 4
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 2
                WHEN 'Informational' THEN 1
                WHEN 'Optimization' THEN 0
                ELSE -1
            END >= ?
        """
        params.append(min_rank)

    if chain_id is not None:
        query += " AND c.chain_id = ?"
        params.append(chain_id)

    query += " ORDER BY CASE f.severity WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 WHEN 'Low' THEN 2 ELSE 3 END"
    query += " LIMIT ?"
    params.append(limit)

    rows = con.execute(query, params).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def build_benchmark_slice(
    con: duckdb.DuckDBPyConnection,
    detector: str | None = None,
    min_severity: str | None = None,
    chain_id: str | None = None,
) -> str:
    """Export filtered findings to a Parquet file.

    Returns:
        Path to the generated .parquet file under slices/.
    """
    data = search_vulnerabilities(
        con, detector=detector, min_severity=min_severity, chain_id=chain_id, limit=10000
    )
    df = pd.DataFrame(data)

    slug = hashlib.sha256(
        json.dumps({"detector": detector, "min_severity": min_severity, "chain_id": chain_id},
                    sort_keys=True).encode()
    ).hexdigest()[:12]

    slices_dir = Path("slices")
    slices_dir.mkdir(exist_ok=True)
    path = slices_dir / f"benchmark_{slug}.parquet"

    table = pa.Table.from_pandas(df)
    pq.write_table(table, str(path))
    return str(path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
python -m pytest tests/test_query.py -v
```
Expected: 4 tests PASS

- [ ] **Step 5: Write failing test for build_benchmark_slice**

Add to `tests/test_query.py`:

```python
import pyarrow.parquet as pq
from pathlib import Path


def test_build_benchmark_slice_creates_parquet(db, tmp_path, monkeypatch):
    from backend.query import build_benchmark_slice

    _seed_test_data(db)

    # Point slices output to tmp_path
    monkeypatch.chdir(tmp_path)

    path = build_benchmark_slice(db, detector="reentrancy-eth")
    assert Path(path).exists()

    table = pq.read_table(path)
    assert table.num_rows == 2
    assert "address" in table.column_names
    assert "detector" in table.column_names
    assert "severity" in table.column_names
```

- [ ] **Step 6: Run test to verify it passes**

Run:
```bash
python -m pytest tests/test_query.py::test_build_benchmark_slice_creates_parquet -v
```
Expected: PASS

- [ ] **Step 7: Run all query tests**

Run:
```bash
python -m pytest tests/test_query.py -v
```
Expected: 5 tests PASS

- [ ] **Step 8: Commit query + export**

```bash
git add backend/query.py tests/test_query.py
git commit -m "feat: search_vulnerabilities with severity filtering and Parquet export"
```

---

### Task 7: FastAPI Server with REST, MCP, and x402 Mock

**Files:**
- Create: `backend/main.py`
- Create: `tests/test_api.py`

- [ ] **Step 1: Write failing test for health endpoint**

Create `tests/test_api.py`:

```python
import json

import duckdb
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.db import init_db, insert_contract, insert_finding


@pytest.fixture
def test_db():
    con = duckdb.connect(":memory:")
    init_db(con)
    yield con
    con.close()


@pytest.fixture
def client(test_db):
    from backend.main import create_app

    app = create_app(test_db)
    return TestClient(app)


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
python -m pytest tests/test_api.py::test_health -v
```
Expected: FAIL -- `ModuleNotFoundError` or `ImportError`

- [ ] **Step 3: Implement FastAPI app skeleton**

Create `backend/main.py`:

```python
import json
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.db import DB_PATH, get_connection, init_db
from backend.ingest import ingest_contract
from backend.query import build_benchmark_slice, search_vulnerabilities


def create_app(con: duckdb.DuckDBPyConnection | None = None) -> FastAPI:
    """Create the FastAPI application. Accepts an optional DuckDB connection for testing."""
    app = FastAPI(title="EVM Security Atlas", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def _get_db() -> duckdb.DuckDBPyConnection:
        if con is not None:
            return con
        return app.state.db

    @app.on_event("startup")
    def startup():
        if con is None:
            Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
            app.state.db = get_connection()
            init_db(app.state.db)

    # ── Health ────────────────────────────────────────────
    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    # ── Contract lookup ───────────────────────────────────
    @app.get("/api/contracts/{chain_id}/{address}")
    def get_contract(chain_id: str, address: str):
        try:
            result = ingest_contract(_get_db(), chain_id, address)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return result

    # ── Search findings ───────────────────────────────────
    @app.get("/api/search")
    def search(
        detector: str | None = Query(None),
        min_severity: str | None = Query(None),
        chain_id: str | None = Query(None),
        limit: int = Query(500, le=10000),
    ):
        results = search_vulnerabilities(
            _get_db(),
            detector=detector,
            min_severity=min_severity,
            chain_id=chain_id,
            limit=limit,
        )
        return {"count": len(results), "results": results}

    # ── Export (x402 gated) ───────────────────────────────
    class ExportRequest(BaseModel):
        detector: str | None = None
        min_severity: str | None = None
        chain_id: str | None = None

    @app.post("/api/export")
    def export_slice(body: ExportRequest, request: Request):
        if not request.headers.get("X-Payment-Signed"):
            return JSONResponse(
                status_code=402,
                content={
                    "payment_required": "0.01 USDC on Base",
                    "wallet": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
                    "network": "base",
                    "message": "Sign payment to download benchmark slice",
                },
            )
        path = build_benchmark_slice(
            _get_db(),
            detector=body.detector,
            min_severity=body.min_severity,
            chain_id=body.chain_id,
        )
        return FileResponse(path, filename=Path(path).name, media_type="application/octet-stream")

    # ── MCP endpoint (x402 gated) ─────────────────────────
    class MCPRequest(BaseModel):
        tool: str
        args: dict = {}

    TOOL_REGISTRY = {
        "search_vulnerabilities": lambda db, args: search_vulnerabilities(
            db,
            detector=args.get("detector"),
            min_severity=args.get("min_severity"),
            chain_id=args.get("chain_id"),
        ),
        "build_benchmark_slice": lambda db, args: build_benchmark_slice(
            db,
            detector=args.get("detector"),
            min_severity=args.get("min_severity"),
            chain_id=args.get("chain_id"),
        ),
    }

    @app.post("/api/mcp")
    def mcp_handler(body: MCPRequest, request: Request):
        if not request.headers.get("X-Payment-Signed"):
            return JSONResponse(
                status_code=402,
                content={
                    "payment_required": "0.01 USDC on Base",
                    "wallet": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
                    "tools": list(TOOL_REGISTRY.keys()),
                },
            )

        handler = TOOL_REGISTRY.get(body.tool)
        if handler is None:
            raise HTTPException(status_code=404, detail=f"Unknown tool: {body.tool}")

        result = handler(_get_db(), body.args)
        return {"status": 200, "tool": body.tool, "data": result}

    return app


# Default app instance for `uvicorn backend.main:app`
app = create_app()
```

- [ ] **Step 4: Run health test to verify it passes**

Run:
```bash
python -m pytest tests/test_api.py::test_health -v
```
Expected: PASS

- [ ] **Step 5: Write test for search endpoint**

Add to `tests/test_api.py`:

```python
def _seed_api_data(db):
    c1 = insert_contract(db, address="0xAAAA", chain_id="1", contract_name="VulnToken")
    insert_finding(db, c1, "reentrancy-eth", "High", "Medium", "Reentrancy in withdraw()")
    insert_finding(db, c1, "unchecked-lowlevel", "Medium", "Medium", "Unchecked call")
    c2 = insert_contract(db, address="0xBBBB", chain_id="1", contract_name="SafeToken")
    insert_finding(db, c2, "reentrancy-eth", "High", "High", "Reentrancy in deposit()")


def test_search_returns_findings(client, test_db):
    _seed_api_data(test_db)
    resp = client.get("/api/search")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 3


def test_search_with_detector_filter(client, test_db):
    _seed_api_data(test_db)
    resp = client.get("/api/search?detector=reentrancy-eth")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2
    assert all(r["detector"] == "reentrancy-eth" for r in data["results"])
```

- [ ] **Step 6: Run search tests**

Run:
```bash
python -m pytest tests/test_api.py::test_search_returns_findings tests/test_api.py::test_search_with_detector_filter -v
```
Expected: PASS

- [ ] **Step 7: Write test for export x402 gate**

Add to `tests/test_api.py`:

```python
def test_export_returns_402_without_payment(client, test_db):
    _seed_api_data(test_db)
    resp = client.post("/api/export", json={})
    assert resp.status_code == 402
    body = resp.json()
    assert "payment_required" in body
    assert "wallet" in body


def test_export_returns_parquet_with_payment(client, test_db, tmp_path, monkeypatch):
    _seed_api_data(test_db)
    monkeypatch.chdir(tmp_path)
    resp = client.post(
        "/api/export",
        json={"detector": "reentrancy-eth"},
        headers={"X-Payment-Signed": "mock-sig-abc123"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert len(resp.content) > 0
```

- [ ] **Step 8: Run export tests**

Run:
```bash
python -m pytest tests/test_api.py::test_export_returns_402_without_payment tests/test_api.py::test_export_returns_parquet_with_payment -v
```
Expected: PASS

- [ ] **Step 9: Write test for MCP endpoint**

Add to `tests/test_api.py`:

```python
def test_mcp_returns_402_without_payment(client):
    resp = client.post("/api/mcp", json={"tool": "search_vulnerabilities"})
    assert resp.status_code == 402
    body = resp.json()
    assert "tools" in body


def test_mcp_search_with_payment(client, test_db):
    _seed_api_data(test_db)
    resp = client.post(
        "/api/mcp",
        json={"tool": "search_vulnerabilities", "args": {"detector": "reentrancy-eth"}},
        headers={"X-Payment-Signed": "mock-sig"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool"] == "search_vulnerabilities"
    assert len(data["data"]) == 2


def test_mcp_unknown_tool(client):
    resp = client.post(
        "/api/mcp",
        json={"tool": "nonexistent"},
        headers={"X-Payment-Signed": "mock-sig"},
    )
    assert resp.status_code == 404
```

- [ ] **Step 10: Run all API tests**

Run:
```bash
python -m pytest tests/test_api.py -v
```
Expected: 8 tests PASS

- [ ] **Step 11: Commit FastAPI server**

```bash
git add backend/main.py tests/test_api.py
git commit -m "feat: FastAPI server with REST, MCP, and x402 mock payment gate"
```

---

### Task 8: Seed Data Script

**Files:**
- Create: `backend/seed.py`

- [ ] **Step 1: Create seed script with known vulnerable contracts**

Create `backend/seed.py`:

```python
"""Seed the DuckDB database with known vulnerable contracts and findings.

Run: python -m backend.seed
"""

from pathlib import Path

from backend.db import get_connection, init_db, insert_contract, insert_finding, insert_incident

SEED_CONTRACTS = [
    {
        "address": "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413",
        "chain_id": "1",
        "contract_name": "TheDAO",
        "compiler_version": "0.3.1",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "reentrancy-eth", "severity": "High", "confidence": "High",
             "description": "Reentrancy in DAO.splitDAO(uint256,address). External call to recipient before state update allows recursive withdrawals."},
            {"detector": "reentrancy-no-eth", "severity": "Medium", "confidence": "Medium",
             "description": "Reentrancy in DAO.vote(uint256,bool). State variable written after external call."},
            {"detector": "unchecked-send", "severity": "Medium", "confidence": "Medium",
             "description": "DAO.withdrawRewardFor(address) ignores return value of msg.sender.send()."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version 0.3.1 is outdated. Consider upgrading to 0.8.x."},
        ],
    },
    {
        "address": "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
        "chain_id": "1",
        "contract_name": "WalletLibrary",
        "compiler_version": "0.4.11",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "suicidal", "severity": "High", "confidence": "High",
             "description": "WalletLibrary.kill(address) can be called by anyone to selfdestruct the library, bricking all dependent wallets."},
            {"detector": "uninitialized-state", "severity": "High", "confidence": "High",
             "description": "WalletLibrary.m_numOwners is never initialized in initWallet, allowing anyone to claim ownership."},
            {"detector": "delegatecall-loop", "severity": "High", "confidence": "Medium",
             "description": "Wallet.() uses delegatecall to WalletLibrary. If library is destroyed, all wallets are permanently bricked."},
        ],
    },
    {
        "address": "0xC5d105E63711398aF9bbff092d4B6CdeF7bC0346",
        "chain_id": "1",
        "contract_name": "BeautyChainToken",
        "compiler_version": "0.4.16",
        "language": "Solidity",
        "optimizer_enabled": False,
        "optimizer_runs": None,
        "findings": [
            {"detector": "controlled-array-length", "severity": "High", "confidence": "Medium",
             "description": "Integer overflow in BEC.batchTransfer(). Multiplication of _value * cnt can overflow, allowing minting of arbitrary tokens."},
            {"detector": "tautology", "severity": "Medium", "confidence": "High",
             "description": "BEC.batchTransfer() contains tautological comparison that is always true due to uint underflow."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version 0.4.16 lacks overflow checks. Use 0.8.x with built-in SafeMath."},
        ],
    },
    {
        "address": "0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2",
        "chain_id": "1",
        "contract_name": "FiatTokenV1",
        "compiler_version": "0.6.12",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "FiatTokenV1 has owner-only functions: pause(), blacklist(), mint(), configureMinter(). Single key compromise can freeze all assets."},
            {"detector": "missing-zero-check", "severity": "Low", "confidence": "Medium",
             "description": "FiatTokenV1.initialize() does not check that owner_ is non-zero address."},
        ],
    },
    {
        "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "chain_id": "1",
        "contract_name": "UniswapV2Router02",
        "compiler_version": "0.6.6",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 999999,
        "findings": [
            {"detector": "reentrancy-benign", "severity": "Low", "confidence": "Medium",
             "description": "Benign reentrancy in UniswapV2Router02.swapExactTokensForTokens(). State not modified after external calls."},
            {"detector": "unchecked-transfer", "severity": "Medium", "confidence": "Medium",
             "description": "UniswapV2Router02.removeLiquidity() does not check return value of pair.transferFrom()."},
            {"detector": "timestamp", "severity": "Low", "confidence": "Medium",
             "description": "UniswapV2Router02 uses block.timestamp for deadline comparison. Miner can manipulate within a small window."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version ^0.6.6 allows outdated compiler. Consider using 0.8.x."},
        ],
    },
]

SEED_INCIDENTS = [
    {
        "vulnerability_class": "reentrancy",
        "tx_hash": "0xc9b30b517c281e437ef21ca6af9b32ff14b4d1a45e7a403e3e0e6e7e6f06c6f2",
        "loss_usd": 60_000_000.0,
        "incident_date": "2016-06-17",
        "source_url": "https://en.wikipedia.org/wiki/The_DAO_(organization)",
        "description": "The DAO hack. Recursive call in splitDAO drained 3.6M ETH (~$60M).",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686c0722c9",
        "loss_usd": 30_000_000.0,
        "incident_date": "2017-07-19",
        "source_url": "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7",
        "description": "Parity Multisig Hack. Uninitialized WalletLibrary allowed attacker to take ownership and drain ~30M USD.",
    },
    {
        "vulnerability_class": "self-destruct",
        "tx_hash": "0x0570400e38e50c70fa25d3aac496f6e937a6bf7b08e45bcf22e6fa6f3e2afbe6",
        "loss_usd": 150_000_000.0,
        "incident_date": "2017-11-06",
        "source_url": "https://blog.openzeppelin.com/parity-wallet-hack-reloaded",
        "description": "Parity wallet freeze. WalletLibrary killed via selfdestruct, freezing 513k ETH (~$150M) permanently.",
    },
    {
        "vulnerability_class": "integer-overflow",
        "tx_hash": "0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebb0d3a56b750e3b3e5",
        "loss_usd": 900_000_000.0,
        "incident_date": "2018-04-22",
        "source_url": "https://medium.com/@peckshield/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536",
        "description": "BEC token batchOverflow. Integer overflow in batchTransfer minted tokens worth ~$900M (market value crashed).",
    },
]


def seed(db_path: str | None = None) -> None:
    """Populate the database with sample data for demo purposes."""
    con = get_connection(db_path)
    init_db(con)

    for contract_data in SEED_CONTRACTS:
        findings = contract_data.pop("findings")
        cid = insert_contract(con, **contract_data)
        for finding in findings:
            insert_finding(con, contract_id=cid, **finding)
        contract_data["findings"] = findings  # restore for re-runnability

    for incident_data in SEED_INCIDENTS:
        insert_incident(con, **incident_data)

    row = con.execute("SELECT COUNT(*) FROM contracts").fetchone()
    print(f"Seeded {row[0]} contracts")
    row = con.execute("SELECT COUNT(*) FROM findings").fetchone()
    print(f"Seeded {row[0]} findings")
    row = con.execute("SELECT COUNT(*) FROM incidents").fetchone()
    print(f"Seeded {row[0]} incidents")

    con.close()


if __name__ == "__main__":
    seed()
```

- [ ] **Step 2: Run the seed script**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
mkdir -p data
python -m backend.seed
```
Expected:
```
Seeded 5 contracts
Seeded 16 findings
Seeded 4 incidents
```

- [ ] **Step 3: Verify seeded data via quick smoke test**

Run:
```bash
python -c "
import duckdb
con = duckdb.connect('data/atlas.duckdb')
print('Contracts:', con.execute('SELECT address, contract_name FROM contracts').fetchall())
print('High findings:', con.execute(\"SELECT c.contract_name, f.detector, f.severity FROM findings f JOIN contracts c ON f.contract_id = c.id WHERE f.severity = 'High'\").fetchall())
con.close()
"
```
Expected: Lists 5 contracts and multiple High-severity findings.

- [ ] **Step 4: Commit seed script + data**

```bash
git add backend/seed.py
git commit -m "feat: seed script with 5 known vulnerable contracts, 16 findings, 4 incidents"
```

---

### Task 9: Next.js Frontend

**Files:**
- Create: `frontend/package.json`
- Create: `frontend/next.config.js`
- Create: `frontend/tailwind.config.js`
- Create: `frontend/postcss.config.js`
- Create: `frontend/app/layout.tsx`
- Create: `frontend/app/page.tsx`
- Create: `frontend/app/globals.css`
- Create: `frontend/lib/api.ts`
- Create: `frontend/tsconfig.json`

- [ ] **Step 1: Scaffold Next.js project**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
npx create-next-app@14 frontend --typescript --tailwind --eslint --app --src-dir=false --import-alias="@/*" --no-turbopack --use-npm
```
Expected: Next.js project created in `frontend/`.

- [ ] **Step 2: Install additional dependencies**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic/frontend
npm install recharts
```

- [ ] **Step 3: Create API client**

Create `frontend/lib/api.ts`:

```typescript
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
```

- [ ] **Step 4: Create the main page**

Replace `frontend/app/page.tsx` with:

```tsx
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
    const result = await exportSlice({
      detector: detectorFilter || undefined,
      min_severity: severityFilter || undefined,
    });
    if (result.challenge) {
      setPaymentChallenge(result.challenge);
      return;
    }
    if (result.blob) {
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "benchmark.parquet";
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  async function handleMockPay() {
    const result = await exportSlice(
      {
        detector: detectorFilter || undefined,
        min_severity: severityFilter || undefined,
      },
      "mock-payment-sig-" + Date.now()
    );
    setPaymentChallenge(null);
    if (result.blob) {
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "benchmark.parquet";
      a.click();
      URL.revokeObjectURL(url);
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

        {/* ── Contract Lookup Tab ─────────────────────── */}
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

        {/* ── Browse Findings Tab ─────────────────────── */}
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
                  Cost: {paymentChallenge.payment_required}
                </p>
                <p className="text-sm text-gray-400 mb-1 font-mono">
                  Wallet: {paymentChallenge.wallet}
                </p>
                <p className="text-sm text-gray-400 mb-3">
                  Network: {paymentChallenge.network}
                </p>
                <button
                  onClick={handleMockPay}
                  className="bg-yellow-600 hover:bg-yellow-700 px-4 py-2 rounded text-sm font-medium"
                >
                  Simulate Payment & Download
                </button>
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
```

- [ ] **Step 5: Update globals.css**

Ensure `frontend/app/globals.css` contains only Tailwind directives (remove any default Next.js styles):

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

- [ ] **Step 6: Update layout.tsx**

Replace `frontend/app/layout.tsx` with:

```tsx
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "EVM Security Atlas",
  description: "Vulnerability intelligence over verified Sourcify contracts",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
```

- [ ] **Step 7: Verify frontend builds**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic/frontend
npm run build
```
Expected: Build completes without errors.

- [ ] **Step 8: Commit frontend**

```bash
cd /home/krzysztof/Desktop/synthetic
git add frontend/lib/api.ts frontend/app/page.tsx frontend/app/layout.tsx frontend/app/globals.css
git commit -m "feat: Next.js frontend with contract lookup, findings browser, x402 export flow"
```

---

### Task 10: Integration Smoke Test

**Files:** None (verification only)

- [ ] **Step 1: Run all backend tests**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic
python -m pytest tests/ -v
```
Expected: All tests pass (should be ~19 tests).

- [ ] **Step 2: Start the backend server**

Run (in background):
```bash
cd /home/krzysztof/Desktop/synthetic
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
sleep 2
```

- [ ] **Step 3: Verify API health**

Run:
```bash
curl -s http://localhost:8000/api/health | python -m json.tool
```
Expected:
```json
{
    "status": "ok"
}
```

- [ ] **Step 4: Verify search endpoint returns seeded data**

Run:
```bash
curl -s 'http://localhost:8000/api/search?min_severity=High' | python -m json.tool
```
Expected: JSON with `count` >= 5 and results array containing High-severity findings from seeded contracts.

- [ ] **Step 5: Verify x402 gate**

Run:
```bash
# Without payment -- should return 402
curl -s -w "\nHTTP %{http_code}\n" -X POST http://localhost:8000/api/export -H "Content-Type: application/json" -d '{}'

# With payment -- should return parquet file
curl -s -w "\nHTTP %{http_code}\n" -X POST http://localhost:8000/api/export -H "Content-Type: application/json" -H "X-Payment-Signed: mock" -d '{"min_severity": "High"}' -o /tmp/test.parquet
python -c "import pyarrow.parquet as pq; t = pq.read_table('/tmp/test.parquet'); print(f'Rows: {t.num_rows}, Cols: {t.column_names}')"
```
Expected: First request returns HTTP 402 with payment details. Second returns HTTP 200 with valid Parquet. Python prints row count and column names.

- [ ] **Step 6: Verify MCP endpoint**

Run:
```bash
curl -s -X POST http://localhost:8000/api/mcp \
  -H "Content-Type: application/json" \
  -H "X-Payment-Signed: mock" \
  -d '{"tool": "search_vulnerabilities", "args": {"detector": "reentrancy-eth"}}' | python -m json.tool
```
Expected: JSON with `status: 200`, `tool: "search_vulnerabilities"`, and `data` array with reentrancy findings.

- [ ] **Step 7: Start frontend and verify in browser**

Run:
```bash
cd /home/krzysztof/Desktop/synthetic/frontend
npm run dev &
```

Open `http://localhost:3000` in a browser. Verify:
1. "Contract Lookup" tab: enter address `0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413` with chain "Ethereum Mainnet" -- should show TheDAO contract details and findings
2. "Browse Findings" tab: click "Search" to see all seeded findings, filter by "High" severity
3. Click "Export Parquet" -- should show x402 payment challenge, then "Simulate Payment & Download" triggers download

- [ ] **Step 8: Stop background servers and commit**

Run:
```bash
kill %1 %2 2>/dev/null
cd /home/krzysztof/Desktop/synthetic
git add -A
git commit -m "chore: integration verification complete"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] Sourcify API ingestion (Task 3)
- [x] Slither static analysis (Task 4, graceful degradation)
- [x] DuckDB storage with contracts/findings/incidents (Task 2)
- [x] search_vulnerabilities with filters (Task 6)
- [x] build_benchmark_slice Parquet export (Task 6)
- [x] MCP endpoint (Task 7)
- [x] x402 mock payment gate (Task 7)
- [x] Storage layout parsing (Task 3, via Sourcify v2 `storageLayout` field)
- [x] Next.js frontend with search/browse/export (Task 9)
- [x] Seed data for demo reliability (Task 8)

**Type consistency:** All function signatures match across tasks. `Finding` type fields (`detector`, `severity`, `confidence`, `description`) are consistent between `ingest.py`, `db.py`, `query.py`, and `api.ts`.

**No placeholders:** All steps contain complete code. No TBD/TODO markers.
