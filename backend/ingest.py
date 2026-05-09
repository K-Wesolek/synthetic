import json
import subprocess
import tempfile
from pathlib import Path

import requests

SOURCIFY_BASE = "https://sourcify.dev/server/v2/contract"


def fetch_verified_contract(chain_id: str, address: str) -> dict:
    """Fetch verified contract source + metadata from Sourcify API v2."""
    url = f"{SOURCIFY_BASE}/{chain_id}/{address}"
    resp = requests.get(
        url,
        params={"fields": "sources,abi,compilation,metadata,storageLayout"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "sources": data.get("sources", {}),
        "abi": data.get("abi", []),
        "compilation": data.get("compilation", {}),
        "metadata": data.get("metadata", {}),
        "storage_layout": data.get("storageLayout"),
        "chain_id": data.get("chainId", chain_id),
        "address": data.get("address", address),
    }
