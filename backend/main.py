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

    # -- Health --
    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    # -- Contract lookup --
    @app.get("/api/contracts/{chain_id}/{address}")
    def get_contract(chain_id: str, address: str):
        try:
            result = ingest_contract(_get_db(), chain_id, address)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        return result

    # -- Search findings --
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

    # -- Export (x402 gated) --
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

    # -- MCP endpoint (x402 gated) --
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
