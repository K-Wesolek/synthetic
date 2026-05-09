import os
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.db import DB_PATH, get_connection, init_db
from backend.ingest import ingest_contract
from backend.query import build_benchmark_slice, search_vulnerabilities

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
    )

    if enable_x402:
        _setup_x402(app)

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

    # -- MCP endpoint (x402 gated in production) --
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
    def mcp_handler(body: MCPRequest):
        handler = TOOL_REGISTRY.get(body.tool)
        if handler is None:
            raise HTTPException(status_code=404, detail=f"Unknown tool: {body.tool}")

        result = handler(_get_db(), body.args)
        return {"status": 200, "tool": body.tool, "data": result}

    return app


# Default app instance for `uvicorn backend.main:app`
app = create_app()
