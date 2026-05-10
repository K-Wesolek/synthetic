import datetime as _dt
import hashlib
import json
from pathlib import Path

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

# Bump when the export schema or taxonomy meaningfully changes.
DATASET_VERSION = "0.3.0"
TAXONOMY_VERSION = "1"

SEVERITY_RANK = {
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Optimization": 0,
}


def dataset_manifest(
    con: duckdb.DuckDBPyConnection | None = None,
    extra: dict | None = None,
) -> dict:
    """Return a manifest dict describing the current dataset version + counts."""
    counts: dict[str, int] = {}
    if con is not None:
        for table in ("contracts", "findings", "incidents", "synthetic_cases"):
            try:
                counts[table] = con.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
            except Exception:
                counts[table] = 0
    out = {
        "dataset_version": DATASET_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
        "generated_at": _dt.datetime.utcnow().isoformat() + "Z",
        "counts": counts,
        "schema": [
            "address", "chain_id", "contract_name", "finding_id",
            "detector", "severity", "confidence", "description",
        ],
    }
    if extra:
        out.update(extra)
    return out


def search_vulnerabilities(
    con: duckdb.DuckDBPyConnection,
    detector: str | None = None,
    min_severity: str | None = None,
    chain_id: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Search findings with optional filters."""
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
    """Export filtered findings to a versioned Parquet file. Returns path.

    Two side-effects accompany the Parquet write:

    * The Parquet KV metadata embeds the dataset manifest (so an offline
      consumer can read it via pyarrow without our API).
    * A sibling ``<slug>.manifest.json`` file is written alongside the
      Parquet for tools that don't parse Parquet metadata.
    """
    filters = {"detector": detector, "min_severity": min_severity, "chain_id": chain_id}
    data = search_vulnerabilities(
        con, detector=detector, min_severity=min_severity, chain_id=chain_id, limit=10000
    )
    df = pd.DataFrame(data)

    slug = hashlib.sha256(json.dumps(filters, sort_keys=True).encode()).hexdigest()[:12]
    slices_dir = Path("slices")
    slices_dir.mkdir(exist_ok=True)
    path = slices_dir / f"benchmark_{DATASET_VERSION}_{slug}.parquet"

    manifest = dataset_manifest(con, extra={"filters": filters, "rows": len(df)})

    table = pa.Table.from_pandas(df)
    # Attach manifest as Parquet kv metadata so offline readers can
    # introspect provenance without a sidecar file.
    schema_with_meta = table.schema.with_metadata(
        {b"atlas_manifest": json.dumps(manifest).encode("utf-8")}
    )
    table = table.replace_schema_metadata(schema_with_meta.metadata)
    pq.write_table(table, str(path))

    sidecar = path.with_suffix(".manifest.json")
    sidecar.write_text(json.dumps(manifest, indent=2))
    return str(path)
