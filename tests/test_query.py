from backend.db import insert_contract, insert_finding


def _seed_test_data(db):
    """Insert sample contracts + findings for query tests."""
    c1 = insert_contract(db, address="0xAAAA", chain_id="1", contract_name="VulnToken")
    insert_finding(db, c1, "reentrancy-eth", "High", "Medium", "Reentrancy in withdraw()")
    insert_finding(db, c1, "unchecked-lowlevel", "Medium", "Medium", "Unchecked call")
    insert_finding(db, c1, "solc-version", "Informational", "High", "Old solc version")

    c2 = insert_contract(db, address="0xBBBB", chain_id="1", contract_name="SafeToken")
    insert_finding(db, c2, "reentrancy-eth", "High", "High", "Reentrancy in deposit()")

    return c1, c2


def test_search_all_findings(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db)
    assert len(results) == 4


def test_search_by_detector(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, detector="reentrancy-eth")
    assert len(results) == 2
    assert all(r["detector"] == "reentrancy-eth" for r in results)


def test_search_by_min_severity(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, min_severity="Medium")
    # Should return High + Medium, not Informational
    assert len(results) == 3
    severities = {r["severity"] for r in results}
    assert "Informational" not in severities


def test_search_by_detector_and_severity(db):
    from backend.query import search_vulnerabilities

    _seed_test_data(db)
    results = search_vulnerabilities(db, detector="reentrancy-eth", min_severity="High")
    assert len(results) == 2


def test_build_benchmark_slice_creates_parquet(db, tmp_path, monkeypatch):
    import pyarrow.parquet as pq
    from pathlib import Path
    from backend.query import build_benchmark_slice

    _seed_test_data(db)

    # Point slices output to tmp_path
    monkeypatch.chdir(tmp_path)

    path = build_benchmark_slice(db, detector="reentrancy-eth")
    assert Path(path).exists()

    table = pq.read_table(path)
    assert table.num_rows == 2
    assert "address" in table.column_names
    assert "detector" in table.column_names
    assert "severity" in table.column_names
