import json
import os
import hashlib

import duckdb

DB_PATH = os.environ.get("ATLAS_DB_PATH", "data/atlas.duckdb")

_SCHEMA_STATEMENTS = [
    # Sequences
    "CREATE SEQUENCE IF NOT EXISTS seq_contracts START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_contract_sources START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_storage_slots START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_findings START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_metadata_keys START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_incidents START 1",
    "CREATE SEQUENCE IF NOT EXISTS seq_synthetic_cases START 1",
    
    # Contracts table - core contract info
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
        abi TEXT,  -- JSON array
        source_code_hash VARCHAR UNIQUE,  -- For deduplication
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(address, chain_id)
    )
    """,
    
    # Source code storage for deduplication and lineage
    """
    CREATE TABLE IF NOT EXISTS contract_sources (
        id INTEGER DEFAULT nextval('seq_contract_sources') PRIMARY KEY,
        contract_id INTEGER NOT NULL,
        file_path VARCHAR NOT NULL,
        content TEXT NOT NULL,
        content_hash VARCHAR NOT NULL,
        FOREIGN KEY (contract_id) REFERENCES contracts(id),
        UNIQUE(contract_id, file_path)
    )
    """,
    
    # Storage slots table for detailed storage layout
    """
    CREATE TABLE IF NOT EXISTS storage_slots (
        id INTEGER DEFAULT nextval('seq_storage_slots') PRIMARY KEY,
        contract_id INTEGER NOT NULL,
        slot_number VARCHAR NOT NULL,
        label VARCHAR,
        type VARCHAR,
        "offset" INTEGER,
        slot_slot VARCHAR,  -- For mappings/arrays
        FOREIGN KEY (contract_id) REFERENCES contracts(id)
    )
    """,
    
    # Metadata key-value pairs for searchable metadata
    """
    CREATE TABLE IF NOT EXISTS contract_metadata (
        id INTEGER DEFAULT nextval('seq_metadata_keys') PRIMARY KEY,
        contract_id INTEGER NOT NULL,
        metadata_key VARCHAR NOT NULL,
        metadata_value TEXT,
        FOREIGN KEY (contract_id) REFERENCES contracts(id)
    )
    """,
    
    # Findings table with PROJECT.md taxonomy columns
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER DEFAULT nextval('seq_findings') PRIMARY KEY,
        contract_id INTEGER NOT NULL,
        detector VARCHAR NOT NULL,
        severity VARCHAR NOT NULL,
        confidence VARCHAR,
        description TEXT,
        first_markdown_element TEXT,
        vulnerability_class VARCHAR,
        layer VARCHAR,
        exploitability VARCHAR,
        reproducibility VARCHAR,
        provenance VARCHAR,
        FOREIGN KEY (contract_id) REFERENCES contracts(id)
    )
    """,
    # Backfill columns on pre-existing schemas (no-ops if already present)
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS vulnerability_class VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS layer VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploitability VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS reproducibility VARCHAR",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS provenance VARCHAR",

    # Incidents table (unchanged for now)
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER DEFAULT nextval('seq_incidents') PRIMARY KEY,
        vulnerability_class VARCHAR NOT NULL,
        tx_hash VARCHAR,
        loss_usd DOUBLE,
        incident_date DATE,
        source_url VARCHAR,
        description TEXT,
        name VARCHAR,
        chain VARCHAR,
        layer VARCHAR,
        exploitability VARCHAR,
        confidence VARCHAR,
        original_classification VARCHAR,
        original_technique VARCHAR,
        provenance VARCHAR DEFAULT 'curated_seed'
    )
    """,
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS name VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS chain VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS layer VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS exploitability VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS confidence VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS original_classification VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS original_technique VARCHAR",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS provenance VARCHAR DEFAULT 'curated_seed'",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_name_date ON incidents(name, incident_date)",

    # Synthetic cases: vulnerable variant + patch pair anchored on a real contract
    """
    CREATE TABLE IF NOT EXISTS synthetic_cases (
        id INTEGER DEFAULT nextval('seq_synthetic_cases') PRIMARY KEY,
        case_uid VARCHAR UNIQUE NOT NULL,
        anchor_contract_id INTEGER,
        anchor_finding_id INTEGER,
        vulnerability_class VARCHAR NOT NULL,
        layer VARCHAR,
        exploitability VARCHAR,
        severity VARCHAR,
        title VARCHAR,
        description TEXT,
        vulnerable_source TEXT NOT NULL,
        patched_source TEXT NOT NULL,
        exploit_precondition TEXT,
        benchmark_task TEXT,
        provenance VARCHAR DEFAULT 'synthetic_augmentation',
        generator VARCHAR,
        generator_version VARCHAR,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (anchor_contract_id) REFERENCES contracts(id),
        FOREIGN KEY (anchor_finding_id) REFERENCES findings(id)
    )
    """,
    
    # Indexes for performance
    "CREATE INDEX IF NOT EXISTS idx_contracts_address_chain ON contracts(address, chain_id)",
    "CREATE INDEX IF NOT EXISTS idx_contracts_source_hash ON contracts(source_code_hash)",
    "CREATE INDEX IF NOT EXISTS idx_contract_sources_contract ON contract_sources(contract_id)",
    "CREATE INDEX IF NOT EXISTS idx_storage_slots_contract ON storage_slots(contract_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_contract ON findings(contract_id)",
    "CREATE INDEX IF NOT EXISTS idx_metadata_contract ON contract_metadata(contract_id)",
    "CREATE INDEX IF NOT EXISTS idx_metadata_key_value ON contract_metadata(metadata_key, metadata_value)",
]


def get_connection(db_path: str | None = None) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection. Uses ATLAS_DB_PATH env var or default.

    If a stale WAL file fails to replay (DuckDB has a known bug replaying
    ALTER TABLE ADD COLUMN entries when reopened), drop the WAL and retry
    rather than leaving the API stuck.
    """
    path = db_path or DB_PATH
    try:
        return duckdb.connect(path)
    except duckdb.InternalException as exc:
        if "WAL" not in str(exc):
            raise
        wal_path = path + ".wal"
        if os.path.exists(wal_path):
            os.remove(wal_path)
        return duckdb.connect(path)


def init_db(con: duckdb.DuckDBPyConnection) -> None:
    """Create all tables and sequences if they don't exist."""
    for stmt in _SCHEMA_STATEMENTS:
        con.execute(stmt)
    # Flush WAL into the main DB file so an abrupt restart (e.g. uvicorn
    # --reload) cannot leave an unreplayable WAL behind.
    con.execute("CHECKPOINT")


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
    source_code_hash: str | None = None,
) -> int:
    """Insert a contract record. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO contracts
            (address, chain_id, contract_name, compiler_version,
             language, optimizer_enabled, optimizer_runs, abi, source_code_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            source_code_hash,
        ],
    ).fetchone()
    return row[0]


def insert_contract_source(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    file_path: str,
    content: str,
) -> int:
    """Insert a contract source file. Returns the new row id."""
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    
    # Check if this exact source file already exists for this contract
    existing = con.execute(
        """
        SELECT id FROM contract_sources 
        WHERE contract_id = ? AND file_path = ? AND content_hash = ?
        """,
        [contract_id, file_path, content_hash],
    ).fetchone()
    
    if existing:
        return existing[0]
    
    row = con.execute(
        """
        INSERT INTO contract_sources
            (contract_id, file_path, content, content_hash)
        VALUES (?, ?, ?, ?)
        RETURNING id
        """,
        [contract_id, file_path, content, content_hash],
    ).fetchone()
    return row[0]


def insert_storage_slot(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    slot_number: str,
    label: str | None = None,
    type_: str | None = None,
    offset: int | None = None,
    slot_slot: str | None = None,
) -> int:
    """Insert a storage slot record. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO storage_slots
            (contract_id, slot_number, label, type, "offset", slot_slot)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [contract_id, slot_number, label, type_, offset, slot_slot],
    ).fetchone()
    return row[0]


def insert_contract_metadata(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    metadata_key: str,
    metadata_value: str | None = None,
) -> int:
    """Insert a contract metadata key-value pair. Returns the new row id."""
    row = con.execute(
        """
        INSERT INTO contract_metadata
            (contract_id, metadata_key, metadata_value)
        VALUES (?, ?, ?)
        RETURNING id
        """,
        [contract_id, metadata_key, metadata_value],
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
    vulnerability_class: str | None = None,
    layer: str | None = None,
    exploitability: str | None = None,
    reproducibility: str | None = None,
    provenance: str | None = None,
) -> int:
    """Insert a finding record with PROJECT.md taxonomy labels. Returns the new row id.

    If taxonomy fields are omitted, they are derived from the detector via
    ``classify_detector``.
    """
    if vulnerability_class is None or layer is None or exploitability is None:
        derived = classify_detector(detector)
        vulnerability_class = vulnerability_class or derived["vulnerability_class"]
        layer = layer or derived["layer"]
        exploitability = exploitability or derived["exploitability"]
    if reproducibility is None:
        reproducibility = "static-only"
    if provenance is None:
        provenance = "static_analysis"

    row = con.execute(
        """
        INSERT INTO findings
            (contract_id, detector, severity, confidence, description, first_markdown_element,
             vulnerability_class, layer, exploitability, reproducibility, provenance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [
            contract_id, detector, severity, confidence, description, first_markdown_element,
            vulnerability_class, layer, exploitability, reproducibility, provenance,
        ],
    ).fetchone()
    return row[0]


# ---------------------------------------------------------------------------
# Taxonomy mapping (PROJECT.md orthogonal buckets)
# ---------------------------------------------------------------------------

VULN_CLASSES = [
    "reentrancy", "access-control", "authz-bypass", "accounting-error",
    "oracle-manipulation", "precision-rounding", "storage-collision",
    "initialization-bug", "upgradeability-flaw", "signature-replay",
    "liquidation-bug", "flash-loan-abuse", "integer-overflow", "self-destruct",
    "unchecked-call", "timestamp-dependence", "dos", "tx-origin", "other",
]

LAYERS = [
    "solidity-source", "compiler-config", "proxy-storage",
    "protocol-logic", "integration", "tokenomics",
]

EXPLOITABILITIES = [
    "direct-drain", "griefing-dos", "privilege-escalation",
    "governance-capture", "frozen-funds", "dilution", "informational",
]

# Map Slither / common detectors -> canonical taxonomy.
_DETECTOR_MAP: dict[str, dict[str, str]] = {
    "reentrancy-eth":          {"vulnerability_class": "reentrancy",        "layer": "protocol-logic",   "exploitability": "direct-drain"},
    "reentrancy-no-eth":       {"vulnerability_class": "reentrancy",        "layer": "protocol-logic",   "exploitability": "direct-drain"},
    "reentrancy-benign":       {"vulnerability_class": "reentrancy",        "layer": "protocol-logic",   "exploitability": "informational"},
    "reentrancy-events":       {"vulnerability_class": "reentrancy",        "layer": "protocol-logic",   "exploitability": "informational"},
    "suicidal":                {"vulnerability_class": "self-destruct",     "layer": "protocol-logic",   "exploitability": "frozen-funds"},
    "uninitialized-state":     {"vulnerability_class": "initialization-bug","layer": "protocol-logic",   "exploitability": "privilege-escalation"},
    "uninitialized-storage":   {"vulnerability_class": "initialization-bug","layer": "proxy-storage",    "exploitability": "privilege-escalation"},
    "delegatecall-loop":       {"vulnerability_class": "upgradeability-flaw","layer": "proxy-storage",   "exploitability": "frozen-funds"},
    "controlled-delegatecall": {"vulnerability_class": "upgradeability-flaw","layer": "proxy-storage",   "exploitability": "direct-drain"},
    "controlled-array-length": {"vulnerability_class": "integer-overflow",  "layer": "solidity-source",  "exploitability": "dilution"},
    "tautology":               {"vulnerability_class": "accounting-error",  "layer": "solidity-source",  "exploitability": "dilution"},
    "centralization-risk":     {"vulnerability_class": "access-control",    "layer": "protocol-logic",   "exploitability": "privilege-escalation"},
    "missing-zero-check":      {"vulnerability_class": "access-control",    "layer": "solidity-source",  "exploitability": "informational"},
    "unchecked-send":          {"vulnerability_class": "unchecked-call",    "layer": "solidity-source",  "exploitability": "griefing-dos"},
    "unchecked-transfer":      {"vulnerability_class": "unchecked-call",    "layer": "integration",      "exploitability": "griefing-dos"},
    "unchecked-lowlevel":      {"vulnerability_class": "unchecked-call",    "layer": "solidity-source",  "exploitability": "griefing-dos"},
    "tx-origin":               {"vulnerability_class": "tx-origin",         "layer": "solidity-source",  "exploitability": "privilege-escalation"},
    "timestamp":               {"vulnerability_class": "timestamp-dependence","layer": "protocol-logic", "exploitability": "informational"},
    "weak-prng":               {"vulnerability_class": "oracle-manipulation","layer": "protocol-logic",  "exploitability": "direct-drain"},
    "arbitrary-send":          {"vulnerability_class": "access-control",    "layer": "protocol-logic",   "exploitability": "direct-drain"},
    "arbitrary-send-eth":      {"vulnerability_class": "access-control",    "layer": "protocol-logic",   "exploitability": "direct-drain"},
    "solc-version":            {"vulnerability_class": "other",             "layer": "compiler-config",  "exploitability": "informational"},
    "pragma":                  {"vulnerability_class": "other",             "layer": "compiler-config",  "exploitability": "informational"},
}


def classify_detector(detector: str) -> dict:
    """Map a Slither/custom detector name to PROJECT.md taxonomy buckets."""
    if detector in _DETECTOR_MAP:
        return _DETECTOR_MAP[detector]
    if detector.startswith("reentrancy"):
        return {"vulnerability_class": "reentrancy", "layer": "protocol-logic", "exploitability": "direct-drain"}
    if detector.startswith("unchecked"):
        return {"vulnerability_class": "unchecked-call", "layer": "solidity-source", "exploitability": "griefing-dos"}
    return {"vulnerability_class": "other", "layer": "solidity-source", "exploitability": "informational"}


def insert_synthetic_case(
    con: duckdb.DuckDBPyConnection,
    case_uid: str,
    vulnerability_class: str,
    title: str,
    vulnerable_source: str,
    patched_source: str,
    anchor_contract_id: int | None = None,
    anchor_finding_id: int | None = None,
    layer: str | None = None,
    exploitability: str | None = None,
    severity: str | None = None,
    description: str | None = None,
    exploit_precondition: str | None = None,
    benchmark_task: str | None = None,
    provenance: str = "synthetic_augmentation",
    generator: str | None = "rule-based-mutator",
    generator_version: str | None = "0.1.0",
) -> int:
    """Insert a synthetic case (vulnerable + patched pair). Returns row id.

    case_uid is a stable, content-derived identifier so re-runs are idempotent.
    """
    existing = con.execute(
        "SELECT id FROM synthetic_cases WHERE case_uid = ?",
        [case_uid],
    ).fetchone()
    if existing:
        return existing[0]

    row = con.execute(
        """
        INSERT INTO synthetic_cases
            (case_uid, anchor_contract_id, anchor_finding_id,
             vulnerability_class, layer, exploitability, severity, title,
             description, vulnerable_source, patched_source,
             exploit_precondition, benchmark_task, provenance,
             generator, generator_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [
            case_uid, anchor_contract_id, anchor_finding_id,
            vulnerability_class, layer, exploitability, severity, title,
            description, vulnerable_source, patched_source,
            exploit_precondition, benchmark_task, provenance,
            generator, generator_version,
        ],
    ).fetchone()
    return row[0]


def list_synthetic_cases(con: duckdb.DuckDBPyConnection, limit: int = 500) -> list[dict]:
    """Return synthetic_cases rows joined with anchor contract info."""
    rows = con.execute(
        """
        SELECT s.id, s.case_uid, s.vulnerability_class, s.layer, s.exploitability,
               s.severity, s.title, s.description, s.exploit_precondition,
               s.benchmark_task, s.provenance, s.generator, s.created_at,
               c.address AS anchor_address, c.contract_name AS anchor_name,
               c.chain_id AS anchor_chain_id
        FROM synthetic_cases s
        LEFT JOIN contracts c ON s.anchor_contract_id = c.id
        ORDER BY s.id
        LIMIT ?
        """,
        [limit],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def get_synthetic_case(con: duckdb.DuckDBPyConnection, case_uid: str) -> dict | None:
    """Return a single synthetic case by case_uid, including source bodies."""
    row = con.execute(
        """
        SELECT s.*, c.address AS anchor_address, c.contract_name AS anchor_name,
               c.chain_id AS anchor_chain_id
        FROM synthetic_cases s
        LEFT JOIN contracts c ON s.anchor_contract_id = c.id
        WHERE s.case_uid = ?
        """,
        [case_uid],
    ).fetchone()
    if row is None:
        return None
    cols = [desc[0] for desc in con.description]
    return dict(zip(cols, row))


def insert_incident(
    con: duckdb.DuckDBPyConnection,
    vulnerability_class: str,
    tx_hash: str | None = None,
    loss_usd: float | None = None,
    incident_date: str | None = None,
    source_url: str | None = None,
    description: str | None = None,
    name: str | None = None,
    chain: str | None = None,
    layer: str | None = None,
    exploitability: str | None = None,
    confidence: str | None = None,
    original_classification: str | None = None,
    original_technique: str | None = None,
    provenance: str = "curated_seed",
) -> int:
    """Insert or update an incident record (idempotent on name+date). Returns row id."""
    if name and incident_date:
        existing = con.execute(
            "SELECT id FROM incidents WHERE name = ? AND incident_date = ?",
            [name, incident_date],
        ).fetchone()
        if existing:
            con.execute(
                """
                UPDATE incidents SET
                    vulnerability_class = ?, tx_hash = ?, loss_usd = ?, source_url = ?,
                    description = ?, chain = ?, layer = ?, exploitability = ?,
                    confidence = ?, original_classification = ?, original_technique = ?,
                    provenance = ?
                WHERE id = ?
                """,
                [vulnerability_class, tx_hash, loss_usd, source_url, description,
                 chain, layer, exploitability, confidence,
                 original_classification, original_technique, provenance, existing[0]],
            )
            return existing[0]
    row = con.execute(
        """
        INSERT INTO incidents
            (vulnerability_class, tx_hash, loss_usd, incident_date, source_url, description,
             name, chain, layer, exploitability, confidence,
             original_classification, original_technique, provenance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        [vulnerability_class, tx_hash, loss_usd, incident_date, source_url, description,
         name, chain, layer, exploitability, confidence,
         original_classification, original_technique, provenance],
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
    if record["abi"] is not None:
        record["abi"] = json.loads(record["abi"])
    # Parse JSON fields if needed
    return record


def get_contract_sources(con: duckdb.DuckDBPyConnection, contract_id: int) -> list[dict]:
    """Fetch all source files for a given contract id."""
    rows = con.execute(
        "SELECT * FROM contract_sources WHERE contract_id = ?",
        [contract_id],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def get_storage_slots(con: duckdb.DuckDBPyConnection, contract_id: int) -> list[dict]:
    """Fetch all storage slots for a given contract id."""
    rows = con.execute(
        "SELECT * FROM storage_slots WHERE contract_id = ? ORDER BY slot_number",
        [contract_id],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def get_contract_metadata(con: duckdb.DuckDBPyConnection, contract_id: int) -> list[dict]:
    """Fetch all metadata for a given contract id."""
    rows = con.execute(
        "SELECT * FROM contract_metadata WHERE contract_id = ?",
        [contract_id],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def get_findings_for_contract(con: duckdb.DuckDBPyConnection, contract_id: int) -> list[dict]:
    """Fetch all findings for a given contract id."""
    rows = con.execute(
        "SELECT * FROM findings WHERE contract_id = ? ORDER BY severity",
        [contract_id],
    ).fetchall()
    cols = [desc[0] for desc in con.description]
    return [dict(zip(cols, row)) for row in rows]


def get_contract_classes(
    con: duckdb.DuckDBPyConnection, contract_id: int
) -> set[str]:
    """Return the set of distinct vulnerability_class values for a contract."""
    rows = con.execute(
        """
        SELECT DISTINCT vulnerability_class
        FROM findings
        WHERE contract_id = ? AND vulnerability_class IS NOT NULL
        """,
        [contract_id],
    ).fetchall()
    return {r[0] for r in rows if r[0]}


def find_similar_contracts(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    limit: int = 8,
) -> list[dict]:
    """Return contracts that share the most vulnerability_class labels with
    the given contract. Score = Jaccard over class sets, broken by raw overlap.

    Excludes the input contract itself.
    """
    target_classes = get_contract_classes(con, contract_id)
    if not target_classes:
        return []

    # Pull (other_id, class) for every other contract in one query.
    rows = con.execute(
        """
        SELECT c.id, c.address, c.chain_id, c.contract_name, c.compiler_version,
               f.vulnerability_class
        FROM contracts c
        JOIN findings f ON f.contract_id = c.id
        WHERE c.id != ? AND f.vulnerability_class IS NOT NULL
        """,
        [contract_id],
    ).fetchall()

    by_contract: dict[int, dict] = {}
    for cid, addr, chain, name, ver, vc in rows:
        bucket = by_contract.setdefault(
            cid,
            {
                "id": cid,
                "address": addr,
                "chain_id": chain,
                "contract_name": name,
                "compiler_version": ver,
                "_classes": set(),
            },
        )
        bucket["_classes"].add(vc)

    scored: list[dict] = []
    for cid, data in by_contract.items():
        overlap = target_classes & data["_classes"]
        if not overlap:
            continue
        union = target_classes | data["_classes"]
        jaccard = len(overlap) / max(1, len(union))
        scored.append({
            "id": data["id"],
            "address": data["address"],
            "chain_id": data["chain_id"],
            "contract_name": data["contract_name"],
            "compiler_version": data["compiler_version"],
            "shared_classes": sorted(overlap),
            "shared_count": len(overlap),
            "similarity": round(jaccard, 3),
        })

    scored.sort(key=lambda r: (-r["similarity"], -r["shared_count"]))
    return scored[:limit]


def find_related_incidents(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    limit: int = 12,
) -> list[dict]:
    """Return incidents whose vulnerability_class matches any class on the
    contract's findings, ordered by recency."""
    classes = get_contract_classes(con, contract_id)
    if not classes:
        return []
    placeholders = ",".join(["?"] * len(classes))
    rows = con.execute(
        f"""
        SELECT id, vulnerability_class, tx_hash, loss_usd, incident_date,
               source_url, description
        FROM incidents
        WHERE vulnerability_class IN ({placeholders})
        ORDER BY incident_date DESC NULLS LAST
        LIMIT ?
        """,
        [*classes, limit],
    ).fetchall()
    cols = [d[0] for d in con.description]
    return [dict(zip(cols, r)) for r in rows]


def get_contract_by_source_hash(con: duckdb.DuckDBPyConnection, source_code_hash: str) -> dict | None:
    """Find a contract by its source code hash (for deduplication)."""
    row = con.execute(
        "SELECT * FROM contracts WHERE source_code_hash = ?",
        [source_code_hash],
    ).fetchone()
    if row is None:
        return None
    cols = [desc[0] for desc in con.description]
    record = dict(zip(cols, row))
    if record["abi"] is not None:
        record["abi"] = json.loads(record["abi"])
    return record