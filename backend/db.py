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
