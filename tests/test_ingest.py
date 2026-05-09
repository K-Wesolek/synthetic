import json
from unittest.mock import patch, MagicMock


MOCK_SOURCIFY_RESPONSE = {
    "chainId": "1",
    "address": "0xDEAD",
    "match": "exact_match",
    "sources": {
        "contracts/Token.sol": {
            "content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Token {}"
        }
    },
    "abi": [{"type": "function", "name": "transfer"}],
    "compilation": {
        "language": "Solidity",
        "compiler": "solc",
        "compilerVersion": "0.8.19+commit.7dd6d404",
        "compilerSettings": {"optimizer": {"enabled": True, "runs": 200}},
        "name": "Token",
        "fullyQualifiedName": "contracts/Token.sol:Token",
    },
    "metadata": {"compiler": {"version": "0.8.19"}},
    "storageLayout": {
        "storage": [{"label": "balance", "slot": "0", "type": "t_uint256"}],
        "types": {"t_uint256": {"label": "uint256", "numberOfBytes": "32"}},
    },
}


def test_fetch_verified_contract_success():
    from backend.ingest import fetch_verified_contract

    mock_resp = MagicMock()
    mock_resp.json.return_value = MOCK_SOURCIFY_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("backend.ingest.requests.get", return_value=mock_resp) as mock_get:
        result = fetch_verified_contract("1", "0xDEAD")

    mock_get.assert_called_once()
    call_url = mock_get.call_args[0][0]
    assert "/v2/contract/1/0xDEAD" in call_url

    assert "contracts/Token.sol" in result["sources"]
    assert result["compilation"]["compilerVersion"] == "0.8.19+commit.7dd6d404"
    assert result["compilation"]["name"] == "Token"
    assert result["abi"] == [{"type": "function", "name": "transfer"}]
    assert result["storage_layout"]["storage"][0]["label"] == "balance"


def test_fetch_verified_contract_not_found():
    from backend.ingest import fetch_verified_contract
    import requests as _requests
    import pytest

    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = _requests.HTTPError("404 Not Found")

    with patch("backend.ingest.requests.get", return_value=mock_resp):
        with pytest.raises(_requests.HTTPError):
            fetch_verified_contract("1", "0x0000000000000000000000000000000000000000")


MOCK_SLITHER_OUTPUT = json.dumps({
    "success": True,
    "error": None,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "description": "Reentrancy in Contract.withdraw()",
                "first_markdown_element": "contracts/Token.sol#L42",
            },
            {
                "check": "unchecked-lowlevel",
                "impact": "Medium",
                "confidence": "Medium",
                "description": "Low-level call in Contract.send()",
                "first_markdown_element": "contracts/Token.sol#L55",
            },
        ]
    },
})


def test_run_slither_analysis_parses_output():
    from backend.ingest import run_slither_analysis

    mock_result = MagicMock()
    mock_result.stdout = MOCK_SLITHER_OUTPUT
    mock_result.returncode = 0

    sources = {
        "contracts/Token.sol": {
            "content": "pragma solidity ^0.8.0;\ncontract Token {}"
        }
    }

    with patch("backend.ingest.subprocess.run", return_value=mock_result) as mock_run:
        with patch("backend.ingest._is_slither_available", return_value=True):
            findings = run_slither_analysis(sources)

    assert len(findings) == 2
    assert findings[0]["detector"] == "reentrancy-eth"
    assert findings[0]["severity"] == "High"
    assert findings[0]["confidence"] == "Medium"
    assert findings[1]["detector"] == "unchecked-lowlevel"
    assert findings[1]["severity"] == "Medium"


def test_run_slither_not_installed_returns_empty():
    from backend.ingest import run_slither_analysis

    sources = {"Token.sol": {"content": "pragma solidity ^0.8.0;"}}

    with patch("backend.ingest._is_slither_available", return_value=False):
        findings = run_slither_analysis(sources)

    assert findings == []
