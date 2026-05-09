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


def _ensure_solc_version(compiler_version: str | None) -> str | None:
    """Install and return the solc binary path for the given compiler version.

    Uses solc-select to manage versions. Returns the binary path or None if
    the version can't be resolved.
    """
    if not compiler_version:
        return None

    # Extract semver from strings like "0.8.19+commit.7dd6d404"
    version = compiler_version.split("+")[0].lstrip("v")

    try:
        # Check if already installed
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=10,
        )
        if version not in result.stdout:
            subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, text=True, timeout=120,
            )
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, text=True, timeout=10,
        )
        return version
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None


def run_slither_analysis(sources: dict, compiler_version: str | None = None) -> list[dict]:
    """Run Slither static analysis on Solidity sources.

    Args:
        sources: mapping of filepath -> {"content": "..."} or filepath -> "source code"
        compiler_version: Solidity compiler version (e.g. "0.8.19+commit.7dd6d404").
                          If provided, solc-select sets the matching solc before analysis.

    Returns:
        List of finding dicts with keys: detector, severity, confidence,
        description, first_markdown_element.
        Returns empty list if Slither is unavailable or analysis fails.
    """
    if not _is_slither_available():
        return []

    _ensure_solc_version(compiler_version)

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


from backend.db import (
    get_contract,
    get_findings_for_contract,
    insert_contract,
    insert_finding,
)


def ingest_contract(
    con,
    chain_id: str,
    address: str,
) -> dict:
    """Fetch, analyze, and store a contract. Returns cached data if already ingested.

    Returns dict with keys: contract (dict), findings (list[dict]).
    """
    existing = get_contract(con, chain_id, address)
    if existing is not None:
        findings = get_findings_for_contract(con, existing["id"])
        return {"contract": existing, "findings": findings}

    data = fetch_verified_contract(chain_id, address)

    compilation = data.get("compilation", {})
    settings = compilation.get("compilerSettings", {})
    optimizer = settings.get("optimizer", {})

    contract_id = insert_contract(
        con,
        address=address,
        chain_id=chain_id,
        contract_name=compilation.get("name"),
        compiler_version=compilation.get("compilerVersion"),
        language=compilation.get("language", "Solidity"),
        optimizer_enabled=optimizer.get("enabled"),
        optimizer_runs=optimizer.get("runs"),
        abi=data.get("abi"),
        metadata=data.get("metadata"),
        storage_layout=data.get("storage_layout"),
    )

    slither_findings = run_slither_analysis(
        data.get("sources", {}),
        compiler_version=compilation.get("compilerVersion"),
    )

    stored_findings = []
    for f in slither_findings:
        fid = insert_finding(
            con,
            contract_id=contract_id,
            detector=f["detector"],
            severity=f["severity"],
            confidence=f.get("confidence"),
            description=f.get("description"),
            first_markdown_element=f.get("first_markdown_element"),
        )
        f["id"] = fid
        f["contract_id"] = contract_id
        stored_findings.append(f)

    contract = get_contract(con, chain_id, address)
    return {"contract": contract, "findings": stored_findings}
