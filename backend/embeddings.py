"""Local embedding pipeline for the EVM Security Atlas explorer.

Builds a unified vector index over three corpora that already live in DuckDB:

  - ``contracts``        (verified Solidity sources from Sourcify)
  - ``synthetic_cases``  (vulnerable + patched generated pairs)
  - ``incidents``        (curated post-mortem hacks)

Strategy: concatenate every available textual signal for a record (contract
sources, finding descriptions, vulnerability_class/layer/exploitability tags,
incident technique), TF-IDF the corpus, then project to a fixed dense vector
via TruncatedSVD. Stored as FLOAT[D] in DuckDB. UMAP gives the 2D projection
for the front-end "Explorer" view.

This module is deliberately dependency-light (numpy + sklearn + umap-learn).
No LLM call needed for v1.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import duckdb
import numpy as np

logger = logging.getLogger("atlas.embeddings")

EMBED_DIM = 128
MODEL_TAG = "tfidf-svd-128-v1"


@dataclass
class Document:
    source_type: str  # 'contract' | 'synthetic' | 'incident'
    source_id: int
    label: str
    text: str
    meta: dict


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

EMBED_SCHEMA = [
    "CREATE SEQUENCE IF NOT EXISTS seq_embeddings START 1",
    """
    CREATE TABLE IF NOT EXISTS embeddings (
        id INTEGER DEFAULT nextval('seq_embeddings') PRIMARY KEY,
        source_type VARCHAR NOT NULL,
        source_id INTEGER NOT NULL,
        model VARCHAR NOT NULL,
        label VARCHAR,
        vector FLOAT[],
        x DOUBLE,
        y DOUBLE,
        cluster INTEGER,
        novelty DOUBLE,
        meta JSON,
        UNIQUE(source_type, source_id, model)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_embeddings_type ON embeddings(source_type)",
]


def init_embeddings_schema(con: duckdb.DuckDBPyConnection) -> None:
    for stmt in EMBED_SCHEMA:
        con.execute(stmt)


# ---------------------------------------------------------------------------
# Corpus collection
# ---------------------------------------------------------------------------

def _collect_contracts(con: duckdb.DuckDBPyConnection) -> list[Document]:
    rows = con.execute(
        """
        SELECT c.id, c.address, c.chain_id, c.contract_name, c.compiler_version,
               STRING_AGG(s.content, '\n\n')
        FROM contracts c
        LEFT JOIN contract_sources s ON s.contract_id = c.id
        GROUP BY c.id, c.address, c.chain_id, c.contract_name, c.compiler_version
        """
    ).fetchall()
    docs: list[Document] = []
    for cid, addr, chain, name, compiler, source in rows:
        # Pull finding tags + descriptions so contracts without verified
        # sources still get a meaningful textual fingerprint.
        finding_rows = con.execute(
            """
            SELECT detector, severity, vulnerability_class, description
            FROM findings WHERE contract_id = ?
            """,
            [cid],
        ).fetchall()
        tag_text = " ".join(
            " ".join(str(x) for x in t[:3] if x) for t in finding_rows
        )
        desc_text = " ".join(t[3] or "" for t in finding_rows)
        slot_rows = con.execute(
            "SELECT label, type FROM storage_slots WHERE contract_id = ?", [cid]
        ).fetchall()
        slot_text = " ".join(f"{l or ''} {t or ''}" for l, t in slot_rows)
        body = source or f"{tag_text} {desc_text} {slot_text}"
        if not body.strip() and not name:
            # Truly empty record — skip rather than add zero-signal noise.
            continue
        text = f"{name or ''} {compiler or ''} {tag_text}\n{body}"
        docs.append(
            Document(
                source_type="contract",
                source_id=cid,
                label=name or addr,
                text=text,
                meta={
                    "address": addr,
                    "chain_id": chain,
                    "name": name,
                    "compiler": compiler,
                    "finding_count": len(finding_rows),
                    "has_source": bool(source),
                },
            )
        )
    return docs


def _collect_synthetic(con: duckdb.DuckDBPyConnection) -> list[Document]:
    rows = con.execute(
        """
        SELECT id, case_uid, vulnerability_class, layer, exploitability, severity,
               title, description, vulnerable_source, patched_source
        FROM synthetic_cases
        """
    ).fetchall()
    docs = []
    for r in rows:
        sid, uid, vc, layer, exp, sev, title, desc, vuln, patched = r
        text = f"{title or ''} {desc or ''} {vc} {layer or ''} {exp or ''} {sev or ''}\n{vuln}"
        docs.append(
            Document(
                source_type="synthetic",
                source_id=sid,
                label=title or uid,
                text=text,
                meta={
                    "case_uid": uid,
                    "vulnerability_class": vc,
                    "layer": layer,
                    "exploitability": exp,
                    "severity": sev,
                },
            )
        )
    return docs


def _collect_incidents(con: duckdb.DuckDBPyConnection) -> list[Document]:
    rows = con.execute(
        """
        SELECT id, name, vulnerability_class, layer, exploitability, chain,
               original_technique, description, loss_usd, incident_date
        FROM incidents WHERE name IS NOT NULL
        """
    ).fetchall()
    docs = []
    for r in rows:
        iid, name, vc, layer, exp, chain, tech, desc, loss, date = r
        text = f"{name} {chain or ''} {vc} {layer or ''} {exp or ''} {tech or ''} {desc or ''}"
        docs.append(
            Document(
                source_type="incident",
                source_id=iid,
                label=name,
                text=text,
                meta={
                    "name": name,
                    "vulnerability_class": vc,
                    "layer": layer,
                    "chain": chain,
                    "loss_usd": float(loss) if loss is not None else None,
                    "incident_date": str(date) if date is not None else None,
                    "technique": tech,
                },
            )
        )
    return docs


def collect_documents(con: duckdb.DuckDBPyConnection) -> list[Document]:
    return _collect_contracts(con) + _collect_synthetic(con) + _collect_incidents(con)


# ---------------------------------------------------------------------------
# Vectorisation
# ---------------------------------------------------------------------------

def _solidity_tokenizer(text: str) -> list[str]:
    """Tokeniser tuned for Solidity / vulnerability descriptions."""
    import re
    return [t for t in re.split(r"[^A-Za-z0-9_]+", text) if t]


def vectorise(docs: list[Document], dim: int = EMBED_DIM) -> tuple[np.ndarray, list[Document]]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import TruncatedSVD
    from sklearn.preprocessing import normalize

    if not docs:
        return np.zeros((0, dim), dtype=np.float32), docs

    tfidf = TfidfVectorizer(
        tokenizer=_solidity_tokenizer,
        token_pattern=None,
        lowercase=True,
        max_features=20000,
        min_df=1,
        ngram_range=(1, 2),
    )
    X = tfidf.fit_transform(d.text for d in docs)
    # SVD requires k < min(n_docs, n_features) — guard for tiny corpora.
    n_components = max(2, min(dim, X.shape[1] - 1, X.shape[0] - 1))
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    V = svd.fit_transform(X)
    V = normalize(V).astype(np.float32)
    if V.shape[1] < dim:
        # Pad to fixed dim so DuckDB column shape stays stable.
        pad = np.zeros((V.shape[0], dim - V.shape[1]), dtype=np.float32)
        V = np.hstack([V, pad])
    return V, docs


def project_2d(V: np.ndarray) -> np.ndarray:
    """UMAP → 2D for the explorer scatter view."""
    if V.shape[0] < 3:
        # Degenerate corpus; fall back to deterministic XY so UI doesn't break.
        return np.array([[i * 0.5, 0.0] for i in range(V.shape[0])], dtype=np.float32)
    import umap
    reducer = umap.UMAP(
        n_components=2,
        metric="cosine",
        n_neighbors=min(15, V.shape[0] - 1),
        min_dist=0.1,
        random_state=42,
    )
    return reducer.fit_transform(V).astype(np.float32)


def cluster(V: np.ndarray, k: int = 8) -> np.ndarray:
    if V.shape[0] < k:
        return np.zeros(V.shape[0], dtype=np.int32)
    from sklearn.cluster import KMeans
    km = KMeans(n_clusters=k, random_state=42, n_init=10)
    return km.fit_predict(V).astype(np.int32)


def novelty_scores(V: np.ndarray, k: int = 5) -> np.ndarray:
    """Mean cosine distance to k-nearest neighbours. Higher = more novel."""
    from sklearn.neighbors import NearestNeighbors
    if V.shape[0] <= 1:
        return np.zeros(V.shape[0], dtype=np.float32)
    n_neighbors = min(k + 1, V.shape[0])
    nn = NearestNeighbors(metric="cosine", n_neighbors=n_neighbors)
    nn.fit(V)
    dists, _ = nn.kneighbors(V)
    return dists[:, 1:].mean(axis=1).astype(np.float32)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def write_embeddings(
    con: duckdb.DuckDBPyConnection,
    docs: list[Document],
    V: np.ndarray,
    XY: np.ndarray,
    clusters: np.ndarray,
    novelty: np.ndarray,
    model: str = MODEL_TAG,
) -> int:
    init_embeddings_schema(con)
    # Wipe previous rows for this model — keeps the table small and fresh.
    con.execute("DELETE FROM embeddings WHERE model = ?", [model])
    rows = []
    for d, v, xy, cl, nv in zip(docs, V, XY, clusters, novelty):
        rows.append(
            (
                d.source_type,
                int(d.source_id),
                model,
                d.label,
                [float(x) for x in v.tolist()],
                float(xy[0]),
                float(xy[1]),
                int(cl),
                float(nv),
                json.dumps(d.meta),
            )
        )
    con.executemany(
        """
        INSERT INTO embeddings
            (source_type, source_id, model, label, vector, x, y, cluster, novelty, meta)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    return len(rows)


def build_index(con: duckdb.DuckDBPyConnection, dim: int = EMBED_DIM) -> dict:
    docs = collect_documents(con)
    if not docs:
        return {"docs": 0, "model": MODEL_TAG, "dim": dim}
    V, docs = vectorise(docs, dim=dim)
    XY = project_2d(V)
    clusters = cluster(V)
    novelty = novelty_scores(V)
    n = write_embeddings(con, docs, V, XY, clusters, novelty)
    by_type: dict[str, int] = {}
    for d in docs:
        by_type[d.source_type] = by_type.get(d.source_type, 0) + 1
    return {
        "docs": n,
        "by_type": by_type,
        "model": MODEL_TAG,
        "dim": dim,
        "novelty_min": float(novelty.min()) if len(novelty) else 0.0,
        "novelty_max": float(novelty.max()) if len(novelty) else 0.0,
        "clusters": int(np.unique(clusters).size),
    }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_vector(
    con: duckdb.DuckDBPyConnection, source_type: str, source_id: int, model: str = MODEL_TAG
) -> np.ndarray | None:
    row = con.execute(
        "SELECT vector FROM embeddings WHERE source_type=? AND source_id=? AND model=?",
        [source_type, source_id, model],
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return np.asarray(row[0], dtype=np.float32)


def find_similar(
    con: duckdb.DuckDBPyConnection,
    source_type: str,
    source_id: int,
    k: int = 12,
    same_type_only: bool = False,
    model: str = MODEL_TAG,
) -> list[dict]:
    """Cosine-similarity top-K against the embedding table."""
    init_embeddings_schema(con)
    q = get_vector(con, source_type, source_id, model)
    if q is None:
        return []
    type_filter = "AND source_type = ?" if same_type_only else ""
    args = [model]
    if same_type_only:
        args.append(source_type)
    rows = con.execute(
        f"""
        SELECT source_type, source_id, label, vector, x, y, cluster, novelty, meta
        FROM embeddings WHERE model = ? {type_filter}
        """,
        args,
    ).fetchall()
    qn = np.linalg.norm(q) or 1.0
    out = []
    for st, sid, label, vec, x, y, cl, nv, meta in rows:
        if st == source_type and sid == source_id:
            continue
        v = np.asarray(vec, dtype=np.float32)
        vn = np.linalg.norm(v) or 1.0
        sim = float(np.dot(q, v) / (qn * vn))
        out.append(
            {
                "source_type": st,
                "source_id": sid,
                "label": label,
                "similarity": sim,
                "x": float(x) if x is not None else None,
                "y": float(y) if y is not None else None,
                "cluster": int(cl) if cl is not None else None,
                "novelty": float(nv) if nv is not None else None,
                "meta": json.loads(meta) if isinstance(meta, str) else meta,
            }
        )
    out.sort(key=lambda r: r["similarity"], reverse=True)
    return out[:k]


def list_projection(
    con: duckdb.DuckDBPyConnection,
    source_types: list[str] | None = None,
    model: str = MODEL_TAG,
    limit: int = 5000,
) -> list[dict]:
    """Flat list of (x, y, label, type, cluster, novelty) for the explorer view."""
    init_embeddings_schema(con)
    where = "WHERE model = ?"
    args: list = [model]
    if source_types:
        where += f" AND source_type IN ({','.join(['?']*len(source_types))})"
        args.extend(source_types)
    rows = con.execute(
        f"""
        SELECT source_type, source_id, label, x, y, cluster, novelty, meta
        FROM embeddings {where}
        ORDER BY novelty DESC
        LIMIT ?
        """,
        [*args, limit],
    ).fetchall()
    out = []
    for st, sid, label, x, y, cl, nv, meta in rows:
        out.append(
            {
                "source_type": st,
                "source_id": sid,
                "label": label,
                "x": float(x) if x is not None else None,
                "y": float(y) if y is not None else None,
                "cluster": int(cl) if cl is not None else None,
                "novelty": float(nv) if nv is not None else None,
                "meta": json.loads(meta) if isinstance(meta, str) else meta,
            }
        )
    return out


def top_novel(
    con: duckdb.DuckDBPyConnection,
    source_type: str | None = None,
    k: int = 25,
    model: str = MODEL_TAG,
) -> list[dict]:
    init_embeddings_schema(con)
    where = "WHERE model = ?"
    args: list = [model]
    if source_type:
        where += " AND source_type = ?"
        args.append(source_type)
    rows = con.execute(
        f"""
        SELECT source_type, source_id, label, novelty, cluster, x, y, meta
        FROM embeddings {where}
        ORDER BY novelty DESC NULLS LAST LIMIT ?
        """,
        [*args, k],
    ).fetchall()
    return [
        {
            "source_type": st,
            "source_id": sid,
            "label": label,
            "novelty": float(nv) if nv is not None else None,
            "cluster": int(cl) if cl is not None else None,
            "x": float(x) if x is not None else None,
            "y": float(y) if y is not None else None,
            "meta": json.loads(meta) if isinstance(meta, str) else meta,
        }
        for st, sid, label, nv, cl, x, y, meta in rows
    ]
