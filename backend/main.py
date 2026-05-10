import logging
import os
import threading
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.analyzer import aggregate_contract_score
from backend.db_enhanced import (
    DB_PATH,
    find_related_incidents,
    find_similar_contracts,
    get_connection,
    get_contract_metadata,
    get_contract_sources,
    get_findings_for_contract,
    get_storage_slots,
    get_synthetic_case,
    init_db,
    list_synthetic_cases,
)
from backend.ingest_enhanced import ingest_contract
from backend.query import (
    DATASET_VERSION,
    TAXONOMY_VERSION,
    build_benchmark_slice,
    dataset_manifest,
    search_vulnerabilities,
)
from backend.synthetic import export_synthetic_parquet, generate as generate_synthetic

logger = logging.getLogger("atlas")
logging.basicConfig(level=os.environ.get("ATLAS_LOG_LEVEL", "INFO"))

# DuckDB only allows one writer at a time. Serialize all writes from this
# process so concurrent /api/contracts (ingest) calls don't error out.
_DB_WRITE_LOCK = threading.Lock()

# x402 configuration via environment
X402_PAY_TO = os.environ.get("X402_PAY_TO", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18")
X402_NETWORK = os.environ.get("X402_NETWORK", "eip155:84532")  # Base Sepolia default
X402_FACILITATOR = os.environ.get("X402_FACILITATOR_URL", "https://x402.org/facilitator")
X402_PRICE_EXPORT = os.environ.get("X402_PRICE_EXPORT", "$0.01")
X402_PRICE_MCP = os.environ.get("X402_PRICE_MCP", "$0.001")


def _setup_x402(app: FastAPI) -> None:
    """Register real x402 payment middleware on paid routes."""
    from x402.http import FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
    from x402.http.middleware.fastapi import PaymentMiddlewareASGI
    from x402.http.types import RouteConfig
    from x402.mechanisms.evm.exact import ExactEvmServerScheme
    from x402.server import x402ResourceServer

    facilitator = HTTPFacilitatorClient(FacilitatorConfig(url=X402_FACILITATOR))
    server = x402ResourceServer(facilitator)
    server.register("eip155:*", ExactEvmServerScheme())

    routes: dict[str, RouteConfig] = {
        "POST /api/export": RouteConfig(
            accepts=[
                PaymentOption(
                    scheme="exact",
                    pay_to=X402_PAY_TO,
                    price=X402_PRICE_EXPORT,
                    network=X402_NETWORK,
                ),
            ],
            mime_type="application/octet-stream",
            description="Export benchmark slice as Parquet",
        ),
        "POST /api/mcp": RouteConfig(
            accepts=[
                PaymentOption(
                    scheme="exact",
                    pay_to=X402_PAY_TO,
                    price=X402_PRICE_MCP,
                    network=X402_NETWORK,
                ),
            ],
            mime_type="application/json",
            description="MCP tool invocation",
        ),
    }

    app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


def create_app(
    con: duckdb.DuckDBPyConnection | None = None,
    enable_x402: bool = True,
) -> FastAPI:
    """Create the FastAPI application.

    Args:
        con: Optional DuckDB connection (for testing).
        enable_x402: If True, add real x402 payment middleware on /api/export and /api/mcp.
                     Set to False in tests so endpoints are freely accessible.
    """
    app = FastAPI(title="EVM Security Atlas", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["payment-required", "x-payment-response"],
    )

    if enable_x402:
        _setup_x402(app)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Convert any unhandled exception into a JSON 500 so the frontend
        # never sees a dropped connection / "failed to fetch".
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "error": exc.__class__.__name__,
                "detail": str(exc) or "internal error",
                "path": request.url.path,
            },
        )

    def _get_db() -> duckdb.DuckDBPyConnection:
        # Hand each request its own cursor so concurrent endpoints don't
        # clobber `description` / cursor state on the shared connection.
        # DuckDB cursors expose the same execute/fetchall API, and writes
        # are still serialised via _DB_WRITE_LOCK.
        base = con if con is not None else app.state.db
        try:
            return base.cursor()
        except Exception:
            return base

    @app.on_event("startup")
    def startup():
        if con is None:
            Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
            try:
                app.state.db = get_connection()
                init_db(app.state.db)
            except Exception as exc:
                logger.exception(
                    "DB init failed (lock contention or stale wal). "
                    "Falling back to read-only.",
                )
                # If another process owns the file, open read-only so the
                # API still serves /api/stats etc. instead of crashing the
                # whole worker.
                app.state.db = duckdb.connect(DB_PATH, read_only=True)
                logger.warning("Opened DB in read-only mode: %s", exc)

    # -- Dataset manifest / version --
    @app.get("/api/dataset/version")
    def dataset_version():
        return dataset_manifest(_get_db())

    # -- Health (DB-aware so the frontend can detect lock contention early) --
    @app.get("/api/health")
    def health():
        db_status = "ok"
        contracts = None
        try:
            contracts = _get_db().execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        except Exception as exc:  # pragma: no cover - reported in payload
            db_status = f"error: {exc}"
        return {"status": "ok", "db": db_status, "contracts": contracts}

    # -- Contract lookup --
    @app.get("/api/contracts/{chain_id}/{address}")
    def get_contract(
        chain_id: str,
        address: str,
        run_slither: bool = Query(True),
    ):
        # Serialize concurrent ingests so DuckDB's single-writer model holds.
        try:
            with _DB_WRITE_LOCK:
                result = ingest_contract(
                    _get_db(), chain_id, address, run_slither=run_slither
                )
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("ingest_contract failed for %s/%s", chain_id, address)
            raise HTTPException(status_code=502, detail=f"ingest failed: {exc}")
        return result

    # -- Search findings (free) --
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

    # -- Export (x402 gated in production) --
    class ExportRequest(BaseModel):
        detector: str | None = None
        min_severity: str | None = None
        chain_id: str | None = None

    @app.post("/api/export")
    def export_slice(body: ExportRequest):
        path = build_benchmark_slice(
            _get_db(),
            detector=body.detector,
            min_severity=body.min_severity,
            chain_id=body.chain_id,
        )
        return FileResponse(path, filename=Path(path).name, media_type="application/octet-stream")

    # -- Contracts list (for atlas dashboard) --
    @app.get("/api/contracts")
    def list_contracts(limit: int = Query(500, le=10000)):
        # Use a thread-local cursor so concurrent requests don't reset
        # `description` on a shared connection.
        cur = _get_db().cursor()
        cur.execute(
            """
            SELECT c.id, c.address, c.chain_id, c.contract_name, c.compiler_version,
                   c.optimizer_enabled, c.optimizer_runs, c.ingested_at,
                   COUNT(f.id) AS finding_count,
                   SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high_count,
                   SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_count
            FROM contracts c
            LEFT JOIN findings f ON f.contract_id = c.id
            GROUP BY c.id, c.address, c.chain_id, c.contract_name, c.compiler_version,
                     c.optimizer_enabled, c.optimizer_runs, c.ingested_at
            ORDER BY high_count DESC NULLS LAST, finding_count DESC NULLS LAST, c.id
            LIMIT ?
            """,
            [limit],
        )
        cols = [d[0] for d in cur.description]
        results = [dict(zip(cols, r)) for r in cur.fetchall()]
        return {"count": len(results), "results": results}

    # -- Full contract page: contract + findings + sources + slots + similar + incidents --
    @app.get("/api/contracts/by-id/{contract_id}/full")
    def contract_full(contract_id: int):
        db = _get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM contracts WHERE id = ?", [contract_id])
        cols = [d[0] for d in cur.description]
        contract_row = cur.fetchone()
        if contract_row is None:
            raise HTTPException(status_code=404, detail="contract not found")
        contract = dict(zip(cols, contract_row))

        findings = get_findings_for_contract(db, contract_id)
        sources = get_contract_sources(db, contract_id)
        # source list can be heavy; trim very-long files for the JSON response.
        for s in sources:
            content = s.get("content") or ""
            if len(content) > 60_000:
                s["content"] = content[:60_000]
                s["truncated"] = True
        slots = get_storage_slots(db, contract_id)
        similar = find_similar_contracts(db, contract_id, limit=8)
        incidents = find_related_incidents(db, contract_id, limit=12)
        score = aggregate_contract_score(db, contract_id)
        # Strip ABI JSON to avoid blowing up the payload.
        contract.pop("abi", None)
        return {
            "contract": contract,
            "score": score,
            "findings": findings,
            "sources": sources,
            "storage_slots": slots,
            "similar_contracts": similar,
            "related_incidents": incidents,
        }

    @app.get("/api/contracts/by-id/{contract_id}/similar")
    def contract_similar(contract_id: int, limit: int = Query(8, le=50)):
        return {"results": find_similar_contracts(_get_db(), contract_id, limit=limit)}

    @app.get("/api/contracts/by-id/{contract_id}/incidents")
    def contract_incidents(contract_id: int, limit: int = Query(20, le=200)):
        return {"results": find_related_incidents(_get_db(), contract_id, limit=limit)}

    @app.get("/api/contracts/by-id/{contract_id}/score")
    def contract_score(contract_id: int):
        return aggregate_contract_score(_get_db(), contract_id)

    # -- Incidents (incident timeline) --
    @app.get("/api/incidents")
    def list_incidents(
        limit: int = Query(500, le=10000),
        vulnerability_class: str | None = Query(None),
        chain: str | None = Query(None),
        min_loss: float | None = Query(None),
        order: str = Query("date_desc", regex="^(date_desc|date_asc|loss_desc|loss_asc)$"),
    ):
        order_sql = {
            "date_desc": "incident_date DESC NULLS LAST",
            "date_asc": "incident_date ASC NULLS LAST",
            "loss_desc": "loss_usd DESC NULLS LAST",
            "loss_asc": "loss_usd ASC NULLS LAST",
        }[order]
        where = []
        args: list = []
        if vulnerability_class:
            where.append("vulnerability_class = ?")
            args.append(vulnerability_class)
        if chain:
            where.append("chain = ?")
            args.append(chain)
        if min_loss is not None:
            where.append("loss_usd >= ?")
            args.append(min_loss)
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        cur = _get_db().cursor()
        cur.execute(
            f"""
            SELECT id, name, vulnerability_class, layer, exploitability, chain,
                   tx_hash, loss_usd, incident_date, source_url, description,
                   confidence, original_classification, original_technique, provenance
            FROM incidents {where_sql}
            ORDER BY {order_sql}
            LIMIT ?
            """,
            [*args, limit],
        )
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
        results = []
        for r in rows:
            rec = dict(zip(cols, r))
            if rec.get("loss_usd") is not None:
                rec["loss_usd"] = float(rec["loss_usd"])
            if rec.get("incident_date") is not None:
                rec["incident_date"] = str(rec["incident_date"])
            results.append(rec)
        return {"count": len(rows), "results": results}

    @app.get("/api/incidents/{incident_id}/full")
    def incident_full(incident_id: int):
        from backend.embeddings import find_similar
        db = _get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM incidents WHERE id = ?", [incident_id])
        cols = [d[0] for d in cur.description]
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="incident not found")
        incident = dict(zip(cols, row))
        if incident.get("loss_usd") is not None:
            incident["loss_usd"] = float(incident["loss_usd"])
        if incident.get("incident_date") is not None:
            incident["incident_date"] = str(incident["incident_date"])
        try:
            similar = find_similar(db, "incident", incident_id, k=8)
        except Exception:
            similar = []
        return {"incident": incident, "similar": similar}

    # -- Aggregate stats (dashboard) --
    @app.get("/api/stats")
    def stats():
        db = _get_db()
        totals = db.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM contracts)         AS contracts,
              (SELECT COUNT(*) FROM findings)          AS findings,
              (SELECT COUNT(*) FROM incidents)         AS incidents,
              (SELECT COUNT(*) FROM synthetic_cases)   AS synthetic_cases,
              (SELECT COALESCE(SUM(loss_usd),0) FROM incidents) AS total_loss_usd
            """
        ).fetchone()
        try:
            embeddings_count = db.execute(
                "SELECT COUNT(*) FROM embeddings"
            ).fetchone()[0]
        except Exception:
            embeddings_count = 0
        try:
            chains = [
                {"chain": c, "n": int(n)}
                for c, n in db.execute(
                    "SELECT chain, COUNT(*) FROM incidents WHERE chain IS NOT NULL GROUP BY chain ORDER BY 2 DESC"
                ).fetchall()
            ]
        except Exception:
            chains = []

        severity = db.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
        ).fetchall()
        by_class = db.execute(
            """
            SELECT COALESCE(vulnerability_class,'unclassified') AS vulnerability_class,
                   COUNT(*) AS n
            FROM findings GROUP BY 1 ORDER BY n DESC
            """
        ).fetchall()
        by_layer = db.execute(
            """
            SELECT COALESCE(layer,'unclassified') AS layer, COUNT(*) AS n
            FROM findings GROUP BY 1 ORDER BY n DESC
            """
        ).fetchall()
        by_compiler = db.execute(
            """
            SELECT COALESCE(SUBSTR(compiler_version,1,3),'unknown') AS major,
                   COUNT(DISTINCT c.id) AS contracts,
                   COUNT(f.id) AS findings
            FROM contracts c LEFT JOIN findings f ON f.contract_id = c.id
            GROUP BY 1 ORDER BY 1
            """
        ).fetchall()
        synth_class = db.execute(
            """
            SELECT vulnerability_class, COUNT(*) AS n
            FROM synthetic_cases GROUP BY 1 ORDER BY n DESC
            """
        ).fetchall()
        timeline = db.execute(
            """
            SELECT vulnerability_class,
                   STRFTIME(incident_date, '%Y') AS year,
                   COUNT(*) AS n,
                   SUM(loss_usd) AS loss_usd
            FROM incidents
            WHERE incident_date IS NOT NULL
            GROUP BY 1,2 ORDER BY year
            """
        ).fetchall()

        return {
            "totals": {
                "contracts": totals[0],
                "findings": totals[1],
                "incidents": totals[2],
                "synthetic_cases": totals[3],
                "embeddings": int(embeddings_count or 0),
                "total_loss_usd": float(totals[4] or 0),
            },
            "severity": [{"severity": s, "n": n} for s, n in severity],
            "by_class": [{"vulnerability_class": k, "n": n} for k, n in by_class],
            "by_layer": [{"layer": k, "n": n} for k, n in by_layer],
            "by_compiler": [
                {"major": m, "contracts": c, "findings": f} for m, c, f in by_compiler
            ],
            "by_chain": chains,
            "synthetic_by_class": [{"vulnerability_class": k, "n": n} for k, n in synth_class],
            "incident_timeline": [
                {"vulnerability_class": v, "year": y, "n": n, "loss_usd": float(l or 0)}
                for v, y, n, l in timeline
            ],
        }

    # -- Synthetic dataset list --
    @app.get("/api/synthetic")
    def synthetic_list(
        vulnerability_class: str | None = Query(None),
        limit: int = Query(500, le=10000),
    ):
        cases = list_synthetic_cases(_get_db(), limit=limit)
        if vulnerability_class:
            cases = [c for c in cases if c["vulnerability_class"] == vulnerability_class]
        return {"count": len(cases), "results": cases}

    # -- Trigger synthetic generation (free, idempotent thanks to case_uid) --
    class GenerateRequest(BaseModel):
        count: int = 24

    @app.post("/api/synthetic/generate")
    def synthetic_generate(body: GenerateRequest):
        if body.count < 1 or body.count > 500:
            raise HTTPException(status_code=400, detail="count must be 1..500")
        inserted = generate_synthetic(_get_db(), count=body.count)
        return {"requested": body.count, "rows": len(inserted), "inserted": inserted}

    # -- Synthetic dataset Parquet export --
    # NOTE: declared BEFORE the catch-all /{case_uid} route so FastAPI matches it first.
    @app.get("/api/synthetic/export.parquet")
    def synthetic_parquet():
        path = export_synthetic_parquet(_get_db())
        return FileResponse(
            path, filename=Path(path).name, media_type="application/octet-stream"
        )

    # -- Synthetic case detail (includes vulnerable + patched bodies) --
    @app.get("/api/synthetic/{case_uid}")
    def synthetic_detail(case_uid: str):
        row = get_synthetic_case(_get_db(), case_uid)
        if row is None:
            raise HTTPException(status_code=404, detail="case not found")
        return row

    # -- x402 endpoint catalog (free) so the frontend can render
    #    "connect your agent" code without hardcoding URLs / prices. --
    @app.get("/api/x402/catalog")
    def x402_catalog():
        return {
            "network": X402_NETWORK,
            "facilitator": X402_FACILITATOR,
            "pay_to": X402_PAY_TO,
            "dataset_version": DATASET_VERSION,
            "taxonomy_version": TAXONOMY_VERSION,
            "endpoints": [
                {
                    "id": "export",
                    "method": "POST",
                    "path": "/api/export",
                    "price": X402_PRICE_EXPORT,
                    "mime_type": "application/octet-stream",
                    "description": "Export benchmark slice as Parquet",
                },
                {
                    "id": "mcp",
                    "method": "POST",
                    "path": "/api/mcp",
                    "price": X402_PRICE_MCP,
                    "mime_type": "application/json",
                    "description": "Call any MCP tool: search, build_benchmark_slice, list_synthetic_cases, generate_synthetic.",
                },
            ],
            "tools": [
                {
                    "name": "search_vulnerabilities",
                    "args": {"detector": "string?", "min_severity": "High|Medium|Low?", "chain_id": "string?"},
                    "description": "Filter the finding index by detector / severity.",
                },
                {
                    "name": "build_benchmark_slice",
                    "args": {"detector": "string?", "min_severity": "string?", "chain_id": "string?"},
                    "description": "Generate and return a Parquet bundle path for the requested slice.",
                },
                {
                    "name": "list_synthetic_cases",
                    "args": {"limit": "int?"},
                    "description": "List vulnerable+patched synthetic cases (case_uid, vulnerable_source, patched_source).",
                },
                {
                    "name": "generate_synthetic",
                    "args": {"count": "int?"},
                    "description": "Trigger the rule-based synthetic generator anchored on real seed contracts.",
                },
                {
                    "name": "score_contract",
                    "args": {"contract_id": "int"},
                    "description": "Aggregate risk score for a contract (0..1) plus severity counts and class set.",
                },
                {
                    "name": "find_similar_contracts",
                    "args": {"contract_id": "int", "limit": "int?"},
                    "description": "Top-k contracts ranked by Jaccard overlap of vulnerability classes.",
                },
                {
                    "name": "compare_to_incidents",
                    "args": {"contract_id": "int", "limit": "int?"},
                    "description": "Historical incidents matching this contract's vulnerability classes.",
                },
                {
                    "name": "list_incidents",
                    "args": {"vulnerability_class": "string?", "year": "string? (e.g. '2024')", "limit": "int?"},
                    "description": "Filter the incidents corpus by class and/or year.",
                },
                {
                    "name": "explore_similar",
                    "args": {"source_type": "contract|synthetic|incident", "source_id": "int", "k": "int?", "same_type_only": "bool?"},
                    "description": "TF-IDF/UMAP similarity over contracts+synthetic+incidents. Returns top-K cosine neighbours with cluster + novelty.",
                },
                {
                    "name": "top_novel",
                    "args": {"source_type": "contract|synthetic|incident?", "k": "int?"},
                    "description": "Top-K most novel records by mean k-NN distance. Use to surface unusual contracts that warrant deeper review.",
                },
                {
                    "name": "atlas_projection",
                    "args": {"types": "string[]?", "limit": "int?"},
                    "description": "2D UMAP projection of the embedding space (x, y, cluster, novelty, meta) for explorer-style UIs.",
                },
            ],
        }

    # -- MCP endpoint (x402 gated in production) --
    class MCPRequest(BaseModel):
        tool: str
        args: dict = {}

    def _list_incidents_tool(db, args):
        cur = db.cursor()
        cur.execute(
            """
            SELECT id, vulnerability_class, tx_hash, loss_usd, incident_date,
                   source_url, description
            FROM incidents
            WHERE (? IS NULL OR vulnerability_class = ?)
              AND (? IS NULL OR STRFTIME(incident_date, '%Y') = ?)
            ORDER BY incident_date DESC NULLS LAST
            LIMIT ?
            """,
            [
                args.get("vulnerability_class"),
                args.get("vulnerability_class"),
                args.get("year"),
                args.get("year"),
                int(args.get("limit", 100)),
            ],
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

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
        "list_synthetic_cases": lambda db, args: list_synthetic_cases(
            db, limit=int(args.get("limit", 500))
        ),
        "generate_synthetic": lambda db, args: generate_synthetic(
            db, count=int(args.get("count", 24))
        ),
        "score_contract": lambda db, args: aggregate_contract_score(
            db, int(args["contract_id"])
        ),
        "find_similar_contracts": lambda db, args: find_similar_contracts(
            db,
            int(args["contract_id"]),
            limit=int(args.get("limit", 8)),
        ),
        "compare_to_incidents": lambda db, args: find_related_incidents(
            db,
            int(args["contract_id"]),
            limit=int(args.get("limit", 12)),
        ),
        "list_incidents": _list_incidents_tool,
        "explore_similar": lambda db, args: __import__(
            "backend.embeddings", fromlist=["find_similar"]
        ).find_similar(
            db,
            args.get("source_type", "incident"),
            int(args["source_id"]),
            k=int(args.get("k", 12)),
            same_type_only=bool(args.get("same_type_only", False)),
        ),
        "top_novel": lambda db, args: __import__(
            "backend.embeddings", fromlist=["top_novel"]
        ).top_novel(
            db,
            source_type=args.get("source_type"),
            k=int(args.get("k", 25)),
        ),
        "atlas_projection": lambda db, args: __import__(
            "backend.embeddings", fromlist=["list_projection"]
        ).list_projection(
            db,
            source_types=args.get("types"),
            limit=int(args.get("limit", 5000)),
        ),
    }

    @app.post("/api/mcp")
    def mcp_handler(body: MCPRequest):
        handler = TOOL_REGISTRY.get(body.tool)
        if handler is None:
            raise HTTPException(status_code=404, detail=f"Unknown tool: {body.tool}")

        result = handler(_get_db(), body.args)
        return {"status": 200, "tool": body.tool, "data": result}

    # -- Admin: import classified hacks CSV (281 incidents) --
    class ImportHacksRequest(BaseModel):
        csv_path: str = "data/hacks_classified.csv"
        review_path: str | None = "data/hacks_batches/review_resolved.csv"

    @app.post("/api/admin/import-hacks")
    def import_hacks(body: ImportHacksRequest):
        import csv as _csv
        from datetime import datetime as _dt
        from backend.db_enhanced import insert_incident as _ins

        db = _get_db()
        # Load review overrides keyed by name
        overrides: dict[str, dict] = {}
        if body.review_path and Path(body.review_path).exists():
            with open(body.review_path) as f:
                for r in _csv.DictReader(f):
                    overrides[r["name"]] = r

        inserted = 0
        skipped = 0
        with _DB_WRITE_LOCK:
            with open(body.csv_path) as f:
                for row in _csv.DictReader(f):
                    name = row["name"]
                    ov = overrides.get(name, {})
                    # Drop incidents that the deep review marked keep=no
                    if ov.get("keep") == "no":
                        skipped += 1
                        continue
                    vc = ov.get("vulnerability_class") or row["vulnerability_class"]
                    layer = ov.get("layer") or row["layer"]
                    exp = ov.get("exploitability") or row["exploitability"]
                    conf = ov.get("confidence") or row["confidence"]
                    notes = ov.get("notes") or row["notes"]
                    sources = ov.get("sources") or ""
                    src_url = sources.split("|")[0].strip() if sources else None
                    try:
                        ts = int(row["date"])
                        date_str = _dt.utcfromtimestamp(ts).date().isoformat()
                    except Exception:
                        date_str = None
                    try:
                        loss = float(row["amount_usd"]) if row["amount_usd"] else None
                    except Exception:
                        loss = None
                    _ins(
                        db,
                        vulnerability_class=vc,
                        loss_usd=loss,
                        incident_date=date_str,
                        source_url=src_url,
                        description=notes,
                        name=name,
                        chain=row.get("chain"),
                        layer=layer,
                        exploitability=exp,
                        confidence=conf,
                        original_classification=row.get("original_classification"),
                        original_technique=row.get("original_technique"),
                        provenance="defillama_curated" if not ov else "curated_review",
                    )
                    inserted += 1
        return {"inserted": inserted, "skipped_keep_no": skipped, "total_seen": inserted + skipped}

    class DatamineRequest(BaseModel):
        limit: int | None = None
        network: bool = True
        run_slither: bool = False

    @app.post("/api/admin/datamine")
    def admin_datamine(body: DatamineRequest):
        from backend.datamine import datamine
        with _DB_WRITE_LOCK:
            results = datamine(
                limit=body.limit,
                network=body.network,
                run_slither=body.run_slither,
                con=_get_db(),
            )
        by_status: dict[str, int] = {}
        for r in results:
            s = r.get("status", "unknown")
            by_status[s] = by_status.get(s, 0) + 1
        return {"processed": len(results), "by_status": by_status, "results": results[-20:]}

    # -- Explorer: TF-IDF + UMAP embedding index over contracts/synthetic/incidents --
    @app.post("/api/admin/build-embeddings")
    def admin_build_embeddings():
        from backend.embeddings import build_index
        with _DB_WRITE_LOCK:
            return build_index(_get_db())

    @app.get("/api/explore/clusters")
    def explore_clusters():
        """Per-cluster summary: dominant class, size, mean novelty, sample labels."""
        db = _get_db()
        try:
            rows = db.execute(
                """
                SELECT cluster, source_type, label, novelty, meta
                FROM embeddings
                """
            ).fetchall()
        except Exception:
            return {"clusters": []}
        from collections import Counter, defaultdict
        import json as _json
        bucket: dict[int, list[dict]] = defaultdict(list)
        for cl, st, label, nv, meta in rows:
            try:
                m = _json.loads(meta) if isinstance(meta, str) else (meta or {})
            except Exception:
                m = {}
            bucket[int(cl) if cl is not None else -1].append({
                "label": label, "type": st, "novelty": nv,
                "vulnerability_class": m.get("vulnerability_class"),
                "loss_usd": m.get("loss_usd"),
                "chain": m.get("chain"),
            })
        out = []
        for cl, items in sorted(bucket.items()):
            classes = Counter(i["vulnerability_class"] for i in items if i["vulnerability_class"])
            types = Counter(i["type"] for i in items)
            losses = [i["loss_usd"] for i in items if i["loss_usd"]]
            novelties = [i["novelty"] for i in items if i["novelty"] is not None]
            top_labels = sorted(items, key=lambda r: -(r["novelty"] or 0))[:5]
            out.append({
                "cluster": cl,
                "size": len(items),
                "by_type": dict(types),
                "dominant_class": classes.most_common(1)[0][0] if classes else None,
                "class_distribution": dict(classes.most_common(5)),
                "total_loss_usd": float(sum(losses)) if losses else 0.0,
                "mean_novelty": float(sum(novelties) / len(novelties)) if novelties else None,
                "sample_labels": [t["label"] for t in top_labels],
            })
        return {"clusters": out}

    @app.get("/api/explore/risk-score")
    def explore_risk_score(
        contract_id: int = Query(...),
        k: int = Query(10, le=50),
    ):
        """Embedding-distance risk score: how close is this contract to known incidents?

        Returns a 0..1 score (higher = closer to historical hacks) plus the
        nearest hacked neighbours and their classes. Pure heuristic — useful
        as a triage signal, not a verdict.
        """
        from backend.embeddings import find_similar
        db = _get_db()
        neighbours = find_similar(db, "contract", contract_id, k=50)
        hacked = [n for n in neighbours if n["source_type"] == "incident"][:k]
        if not hacked:
            return {"contract_id": contract_id, "score": 0.0, "neighbours": [], "note": "no incident neighbours found"}
        score = sum(n["similarity"] for n in hacked) / len(hacked)
        from collections import Counter
        classes = Counter(n["meta"].get("vulnerability_class") for n in hacked if n["meta"].get("vulnerability_class"))
        return {
            "contract_id": contract_id,
            "score": round(float(score), 3),
            "neighbour_count": len(hacked),
            "class_distribution": dict(classes.most_common()),
            "neighbours": [
                {
                    "incident_id": n["source_id"],
                    "name": n["label"],
                    "similarity": n["similarity"],
                    "vulnerability_class": n["meta"].get("vulnerability_class"),
                    "loss_usd": n["meta"].get("loss_usd"),
                    "incident_date": n["meta"].get("incident_date"),
                }
                for n in hacked
            ],
        }

    @app.get("/api/explore/find-unhacked-siblings")
    def explore_unhacked_siblings(
        incident_id: int = Query(...),
        k: int = Query(15, le=100),
    ):
        """For a known hack, return verified contracts in the same embedding region.

        Use case: the hack revealed a vulnerability pattern; here are deployed
        contracts that look structurally similar but haven't been exploited yet.
        """
        from backend.embeddings import find_similar
        db = _get_db()
        all_neighbours = find_similar(db, "incident", incident_id, k=k * 4)
        contracts = [n for n in all_neighbours if n["source_type"] == "contract"][:k]
        return {"incident_id": incident_id, "count": len(contracts), "results": contracts}

    @app.get("/api/incidents/export.parquet")
    def incidents_parquet():
        import pandas as _pd
        import pyarrow as _pa
        import pyarrow.parquet as _pq
        from tempfile import NamedTemporaryFile
        cur = _get_db()
        df = cur.execute(
            """
            SELECT id, name, vulnerability_class, layer, exploitability, chain,
                   loss_usd, incident_date, original_classification,
                   original_technique, confidence, source_url, description,
                   provenance
            FROM incidents
            ORDER BY incident_date DESC NULLS LAST
            """
        ).fetch_df()
        tmp = NamedTemporaryFile(suffix=".parquet", delete=False)
        _pq.write_table(_pa.Table.from_pandas(df), tmp.name)
        return FileResponse(
            tmp.name,
            filename=f"atlas_incidents_{DATASET_VERSION}.parquet",
            media_type="application/octet-stream",
        )

    @app.get("/api/explore/at-risk-watchlist")
    def explore_at_risk(
        k: int = Query(20, le=100),
        min_score: float = Query(0.30),
    ):
        """Rank verified contracts by closeness to historical hacks.

        For every contract we look up the K nearest incident neighbours in
        embedding space, average their cosine similarity, and return the
        ranked list. This is the explorer's "who looks like the next victim"
        view.
        """
        from backend.embeddings import find_similar
        db = _get_db()
        contracts = db.execute(
            """
            SELECT id, address, chain_id, contract_name FROM contracts
            ORDER BY id
            """
        ).fetchall()
        out = []
        for cid, addr, chain, name in contracts:
            neigh = find_similar(db, "contract", cid, k=20)
            hacks = [n for n in neigh if n["source_type"] == "incident"][:k]
            if not hacks:
                continue
            score = sum(n["similarity"] for n in hacks) / len(hacks)
            if score < min_score:
                continue
            top = hacks[0]
            from collections import Counter
            classes = Counter(n["meta"].get("vulnerability_class") for n in hacks if n["meta"].get("vulnerability_class"))
            out.append({
                "contract_id": cid,
                "address": addr,
                "chain_id": chain,
                "contract_name": name,
                "risk_score": round(float(score), 3),
                "neighbour_count": len(hacks),
                "dominant_class": classes.most_common(1)[0][0] if classes else None,
                "top_match": {
                    "incident_id": top["source_id"],
                    "name": top["label"],
                    "similarity": top["similarity"],
                    "vulnerability_class": top["meta"].get("vulnerability_class"),
                    "loss_usd": top["meta"].get("loss_usd"),
                },
            })
        out.sort(key=lambda r: -r["risk_score"])
        return {"count": len(out), "results": out[:k]}

    @app.get("/api/timeline")
    def timeline_by_month(
        granularity: str = Query("month", regex="^(month|quarter|year)$"),
    ):
        """Loss + incident-count time series for the dashboard timeline."""
        bucket_sql = {
            "month": "STRFTIME(incident_date, '%Y-%m')",
            "quarter": "STRFTIME(incident_date, '%Y') || '-Q' || CAST(((CAST(STRFTIME(incident_date,'%m') AS INTEGER)-1)//3 + 1) AS VARCHAR)",
            "year": "STRFTIME(incident_date, '%Y')",
        }[granularity]
        cur = _get_db()
        rows = cur.execute(
            f"""
            SELECT {bucket_sql} AS bucket,
                   COUNT(*) AS n,
                   COALESCE(SUM(loss_usd), 0) AS loss_usd,
                   vulnerability_class
            FROM incidents
            WHERE incident_date IS NOT NULL
            GROUP BY 1, 4
            ORDER BY 1
            """
        ).fetchall()
        return {
            "granularity": granularity,
            "results": [
                {"bucket": b, "n": int(n), "loss_usd": float(l or 0), "vulnerability_class": vc}
                for b, n, l, vc in rows
            ],
        }

    @app.get("/api/explore/projection")
    def explore_projection(
        types: str | None = Query(None, description="comma-separated subset: contract,synthetic,incident"),
        limit: int = Query(5000, le=20000),
    ):
        from backend.embeddings import list_projection
        type_list = [t.strip() for t in types.split(",")] if types else None
        return {"results": list_projection(_get_db(), source_types=type_list, limit=limit)}

    @app.get("/api/explore/similar")
    def explore_similar(
        source_type: str = Query(...),
        source_id: int = Query(...),
        k: int = Query(12, le=100),
        same_type_only: bool = Query(False),
    ):
        from backend.embeddings import find_similar
        results = find_similar(
            _get_db(), source_type, source_id, k=k, same_type_only=same_type_only
        )
        return {"results": results, "count": len(results)}

    @app.get("/api/explore/novel")
    def explore_novel(
        source_type: str | None = Query(None),
        k: int = Query(25, le=200),
    ):
        from backend.embeddings import top_novel
        return {"results": top_novel(_get_db(), source_type=source_type, k=k)}

    return app


# Default app instance for `uvicorn backend.main:app`
app = create_app()
