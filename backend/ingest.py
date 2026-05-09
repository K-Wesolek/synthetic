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


def _is_slither_available() -> bool:
    """Check if slither CLI is installed and runnable."""
    try:
        subprocess.run(["slither", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def run_slither_analysis(sources: dict) -> list[dict]:
    """Run Slither static analysis on Solidity sources.

    Args:
        sources: mapping of filepath -> {"content": "..."} or filepath -> "source code"

    Returns:
        List of finding dicts with keys: detector, severity, confidence,
        description, first_markdown_element.
        Returns empty list if Slither is unavailable or analysis fails.
    """
    if not _is_slither_available():
        return []

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        sol_files = []

        for filepath, source_data in sources.items():
            content = source_data["content"] if isinstance(source_data, dict) else source_data
            full_path = tmp / filepath
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            if filepath.endswith(".sol"):
                sol_files.append(str(full_path))

        if not sol_files:
            return []

        try:
            result = subprocess.run(
                ["slither", sol_files[0], "--json", "-"],
                capture_output=True,
                text=True,
                cwd=str(tmp),
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return []

        output_text = result.stdout
        if not output_text:
            return []

        try:
            output = json.loads(output_text)
            detectors = output.get("results", {}).get("detectors", [])
            return [
                {
                    "detector": d.get("check", "unknown"),
                    "severity": d.get("impact", "Unknown"),
                    "confidence": d.get("confidence", "Unknown"),
                    "description": d.get("description", ""),
                    "first_markdown_element": d.get("first_markdown_element", ""),
                }
                for d in detectors
            ]
        except (json.JSONDecodeError, KeyError):
            return []
