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
    """Export filtered findings to a Parquet file. Returns path to the .parquet file."""
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
