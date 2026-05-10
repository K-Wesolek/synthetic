"""Tests for the synthetic dataset generator and the new dashboard endpoints."""

import duckdb
import pytest
from fastapi.testclient import TestClient

from backend.db_enhanced import (
    classify_detector,
    init_db as init_enhanced,
    insert_contract,
    insert_finding,
    insert_incident,
    list_synthetic_cases,
)
from backend.synthetic import generate, export_synthetic_parquet, MUTATIONS


@pytest.fixture
def edb():
    """Fresh in-memory DB initialised with the enhanced schema + a tiny seed."""
    con = duckdb.connect(":memory:")
    init_enhanced(con)

    cid = insert_contract(
        con,
        address="0xAAAA",
        chain_id="1",
        contract_name="VulnToken",
        compiler_version="0.8.20",
    )
    insert_finding(
        con, contract_id=cid, detector="reentrancy-eth", severity="High",
        confidence="High", description="reentrancy in withdraw",
    )
    insert_finding(
        con, contract_id=cid, detector="missing-zero-check", severity="Low",
        confidence="Medium", description="zero check missing",
    )
    insert_incident(
        con, vulnerability_class="reentrancy", loss_usd=1_000_000.0,
        incident_date="2020-01-01", description="test incident",
    )
    yield con
    con.close()


# ---- taxonomy + finding insert ---------------------------------------------

def test_classify_detector_known():
    t = classify_detector("reentrancy-eth")
    assert t["vulnerability_class"] == "reentrancy"
    assert t["layer"] == "protocol-logic"
    assert t["exploitability"] == "direct-drain"


def test_classify_detector_unknown_returns_other():
    t = classify_detector("totally-made-up-detector")
    assert t["vulnerability_class"] == "other"
    assert t["layer"] == "solidity-source"


def test_insert_finding_autoclassifies(edb):
    rows = edb.execute(
        "SELECT detector, vulnerability_class, layer, exploitability FROM findings"
    ).fetchall()
    assert ("reentrancy-eth", "reentrancy", "protocol-logic", "direct-drain") in rows


# ---- synthetic generation --------------------------------------------------

def test_generate_creates_cases(edb):
    inserted = generate(edb, count=8)
    assert len(inserted) == 8
    cases = list_synthetic_cases(edb, limit=100)
    # generate covers all mutation templates round-robin
    classes = {c["vulnerability_class"] for c in cases}
    assert classes >= {m.vulnerability_class for m in MUTATIONS[:8]}
    # Every case must have both source bodies
    rows = edb.execute(
        "SELECT vulnerable_source, patched_source FROM synthetic_cases"
    ).fetchall()
    for v, p in rows:
        assert "pragma solidity" in v
        assert "pragma solidity" in p
        assert v != p, "vulnerable and patched bodies must differ"


def test_generate_is_idempotent(edb):
    generate(edb, count=4)
    n1 = edb.execute("SELECT COUNT(*) FROM synthetic_cases").fetchone()[0]
    generate(edb, count=4)
    n2 = edb.execute("SELECT COUNT(*) FROM synthetic_cases").fetchone()[0]
    assert n1 == n2 == 4


def test_export_synthetic_parquet(edb, tmp_path, monkeypatch):
    generate(edb, count=4)
    monkeypatch.chdir(tmp_path)
    path = export_synthetic_parquet(edb, out_dir="slices")
    # Versioned filename now: synthetic_dataset_<version>.parquet
    assert path.startswith("slices/synthetic_dataset_")
    assert path.endswith(".parquet")
    import os
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0


# ---- API endpoints ---------------------------------------------------------

@pytest.fixture
def api(edb):
    from backend.main import create_app
    return TestClient(create_app(edb, enable_x402=False))


def test_stats_endpoint(api, edb):
    generate(edb, count=8)
    resp = api.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totals"]["contracts"] >= 1
    assert data["totals"]["synthetic_cases"] == 8
    assert data["totals"]["incidents"] >= 1
    assert any(s["severity"] == "High" for s in data["severity"])
    assert any(c["vulnerability_class"] == "reentrancy" for c in data["by_class"])


def test_contracts_list_endpoint(api):
    resp = api.get("/api/contracts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 1
    row = data["results"][0]
    assert "high_count" in row and "finding_count" in row


def test_incidents_endpoint(api):
    resp = api.get("/api/incidents")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] >= 1


def test_synthetic_endpoint_filter(api, edb):
    generate(edb, count=8)
    resp = api.get("/api/synthetic?vulnerability_class=reentrancy")
    assert resp.status_code == 200
    data = resp.json()
    assert all(r["vulnerability_class"] == "reentrancy" for r in data["results"])
    assert data["count"] >= 1


def test_synthetic_detail_endpoint(api, edb):
    generate(edb, count=4)
    cases = list_synthetic_cases(edb, limit=4)
    uid = cases[0]["case_uid"]
    resp = api.get(f"/api/synthetic/{uid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["vulnerable_source"]
    assert body["patched_source"]
    assert body["case_uid"] == uid


def test_synthetic_detail_404(api):
    resp = api.get("/api/synthetic/does_not_exist")
    assert resp.status_code == 404


def test_synthetic_generate_endpoint(api, edb):
    resp = api.post("/api/synthetic/generate", json={"count": 8})
    assert resp.status_code == 200
    body = resp.json()
    assert body["requested"] == 8
    assert body["rows"] == 8
    assert edb.execute("SELECT COUNT(*) FROM synthetic_cases").fetchone()[0] == 8


def test_synthetic_parquet_endpoint(api, edb, tmp_path, monkeypatch):
    generate(edb, count=4)
    monkeypatch.chdir(tmp_path)
    resp = api.get("/api/synthetic/export.parquet")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert len(resp.content) > 0


def test_mcp_list_synthetic(api, edb):
    generate(edb, count=4)
    resp = api.post(
        "/api/mcp",
        json={"tool": "list_synthetic_cases", "args": {"limit": 100}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["tool"] == "list_synthetic_cases"
    assert len(body["data"]) == 4
