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


def _seed_api_data(db):
    c1 = insert_contract(db, address="0xAAAA", chain_id="1", contract_name="VulnToken")
    insert_finding(db, c1, "reentrancy-eth", "High", "Medium", "Reentrancy in withdraw()")
    insert_finding(db, c1, "unchecked-lowlevel", "Medium", "Medium", "Unchecked call")
    c2 = insert_contract(db, address="0xBBBB", chain_id="1", contract_name="SafeToken")
    insert_finding(db, c2, "reentrancy-eth", "High", "High", "Reentrancy in deposit()")


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


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
