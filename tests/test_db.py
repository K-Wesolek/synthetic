import duckdb


def test_init_db_creates_tables(db):
    tables = db.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
    ).fetchall()
    table_names = {row[0] for row in tables}
    assert "contracts" in table_names
    assert "findings" in table_names
    assert "incidents" in table_names


from backend.db import insert_contract, get_contract


def test_insert_and_get_contract(db):
    cid = insert_contract(
        db,
        address="0xDEAD",
        chain_id="1",
        contract_name="TestToken",
        compiler_version="0.8.19",
        optimizer_enabled=True,
        optimizer_runs=200,
        abi=[{"type": "function", "name": "transfer"}],
    )
    assert cid == 1

    contract = get_contract(db, chain_id="1", address="0xDEAD")
    assert contract is not None
    assert contract["contract_name"] == "TestToken"
    assert contract["compiler_version"] == "0.8.19"
    assert contract["optimizer_enabled"] is True
    assert contract["abi"] == [{"type": "function", "name": "transfer"}]


from backend.db import insert_finding, get_findings_for_contract


def test_insert_and_get_findings(db):
    cid = insert_contract(db, address="0xBEEF", chain_id="1")
    fid = insert_finding(
        db,
        contract_id=cid,
        detector="reentrancy-eth",
        severity="High",
        confidence="Medium",
        description="Reentrancy in withdraw()",
    )
    assert fid == 1

    findings = get_findings_for_contract(db, cid)
    assert len(findings) == 1
    assert findings[0]["detector"] == "reentrancy-eth"
    assert findings[0]["severity"] == "High"
    assert findings[0]["description"] == "Reentrancy in withdraw()"


import duckdb as _duckdb
import pytest


def test_duplicate_contract_raises(db):
    insert_contract(db, address="0xAAAA", chain_id="1")
    with pytest.raises(_duckdb.ConstraintException):
        insert_contract(db, address="0xAAAA", chain_id="1")
