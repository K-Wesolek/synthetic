from unittest.mock import patch, MagicMock
from tests.test_ingest import MOCK_SOURCIFY_RESPONSE


def test_ingest_contract_stores_in_db(db):
    from backend.ingest import ingest_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp):
        with patch("backend.ingest._is_slither_available", return_value=False):
            result = ingest_contract(db, "1", "0xDEAD")

    assert result["contract"]["contract_name"] == "Token"
    assert result["contract"]["compiler_version"] == "0.8.19+commit.7dd6d404"
    assert result["contract"]["address"] == "0xDEAD"
    assert isinstance(result["findings"], list)


def test_ingest_contract_returns_cached_on_second_call(db):
    from backend.ingest import ingest_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp) as mock_get:
        with patch("backend.ingest._is_slither_available", return_value=False):
            ingest_contract(db, "1", "0xDEAD")
            result = ingest_contract(db, "1", "0xDEAD")

    # Sourcify should only be called once -- second call reads from DB cache
    assert mock_get.call_count == 1
    assert result["contract"]["contract_name"] == "Token"
