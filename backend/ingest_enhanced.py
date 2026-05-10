import json
import subprocess
import tempfile
import hashlib
from pathlib import Path

import requests

from backend.analyzer import (
    insert_heuristic_findings,
    recompute_confidence_scores,
)
from backend.db_enhanced import (
    get_contract,
    get_findings_for_contract,
    insert_contract,
    insert_finding,
    insert_contract_source,
    insert_storage_slot,
    insert_contract_metadata,
    get_contract_by_source_hash,
)

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


def ingest_contract(
    con,
    chain_id: str,
    address: str,
    run_slither: bool = True,
) -> dict:
    """Fetch, analyze, and store a contract. Returns cached data if already ingested.

    Args:
        con: DuckDB connection.
        chain_id: numeric chain id ("1" for mainnet, etc.).
        address: contract address (0x...).
        run_slither: if False, skip the Slither analysis step. Useful for fast
            lookups in the demo when solc-select / slither isn't installed
            and would otherwise stall the request for several seconds.

    Returns dict with keys: contract (dict), findings (list[dict]).
    """
    # Check if contract already exists
    existing = get_contract(con, chain_id, address)
    if existing is not None:
        findings = get_findings_for_contract(con, existing["id"])
        return {"contract": existing, "findings": findings}

    # Fetch contract data from Sourcify
    data = fetch_verified_contract(chain_id, address)
    
    # Calculate source code hash for deduplication
    sources = data.get("sources", {})
    combined_source = ""
    for filepath in sorted(sources.keys()):  # Sort for consistent hashing
        source_data = sources[filepath]
        content = source_data["content"] if isinstance(source_data, dict) else source_data
        combined_source += f"{filepath}:::{content}\n"
    
    source_code_hash = hashlib.sha256(combined_source.encode()).hexdigest()
    
    # Check if we already have this exact source code (deduplication)
    existing_by_hash = get_contract_by_source_hash(con, source_code_hash)
    if existing_by_hash is not None:
        # Return the existing contract with the same source code
        findings = get_findings_for_contract(con, existing_by_hash["id"])
        return {"contract": existing_by_hash, "findings": findings}

    # Extract compilation info
    compilation = data.get("compilation", {})
    settings = compilation.get("compilerSettings", {})
    optimizer = settings.get("optimizer", {})

    # Insert contract record
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
        source_code_hash=source_code_hash,
    )

    # Store source files for deduplication and lineage tracking
    for filepath, source_data in sources.items():
        content = source_data["content"] if isinstance(source_data, dict) else source_data
        insert_contract_source(con, contract_id, filepath, content)

    # Parse and store storage layout
    storage_layout = data.get("storage_layout")
    if storage_layout and isinstance(storage_layout, dict):
        # Handle different storage layout formats
        if "storage" in storage_layout and isinstance(storage_layout["storage"], list):
            for slot_info in storage_layout["storage"]:
                insert_storage_slot(
                    con,
                    contract_id=contract_id,
                    slot_number=str(slot_info.get("slot", "")),
                    label=slot_info.get("label"),
                    type_=slot_info.get("type"),
                    offset=slot_info.get("offset"),
                    slot_slot=slot_info.get("slot")  # For nested mappings
                )
        # Also handle the format where storage is a dict with slot numbers as keys
        elif isinstance(storage_layout, dict):
            for slot_key, slot_info in storage_layout.items():
                if slot_key.isdigit() or (isinstance(slot_key, str) and slot_key.replace('.', '').isdigit()):
                    insert_storage_slot(
                        con,
                        contract_id=contract_id,
                        slot_number=str(slot_key),
                        label=slot_info.get("label") if isinstance(slot_info, dict) else None,
                        type_=slot_info.get("type") if isinstance(slot_info, dict) else None,
                    )

    # Extract and store metadata as key-value pairs
    metadata = data.get("metadata")
    if metadata and isinstance(metadata, dict):
        def flatten_metadata(obj, prefix=""):
            items = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, (dict, list)):
                        items.extend(flatten_metadata(v, new_key))
                    else:
                        items.append((new_key, str(v) if v is not None else ""))
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    new_key = f"{prefix}[{i}]"
                    if isinstance(v, (dict, list)):
                        items.extend(flatten_metadata(v, new_key))
                    else:
                        items.append((new_key, str(v) if v is not None else ""))
            else:
                items.append((prefix, str(obj) if obj is not None else ""))
            return items
        
        flat_metadata = flatten_metadata(metadata)
        for key, value in flat_metadata:
            if key and value is not None:  # Skip empty keys
                insert_contract_metadata(con, contract_id, key, value)

    # Run Slither analysis (skippable so a single contract lookup never
    # stalls when slither/solc-select aren't installed).
    if run_slither:
        try:
            slither_findings = run_slither_analysis(
                data.get("sources", {}),
                compiler_version=compilation.get("compilerVersion"),
            )
        except Exception:
            slither_findings = []
    else:
        slither_findings = []

    # Store findings
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

    # Always run heuristic detectors (Slither-independent). These cover
    # patterns Slither doesn't ship with by default and produce findings
    # tagged with provenance="heuristic".
    insert_heuristic_findings(con, contract_id, sources)

    # Refresh confidence scores for this contract's findings.
    recompute_confidence_scores(con)

    # Return the stored contract and findings (re-fetch so heuristic ones
    # are included).
    contract = get_contract(con, chain_id, address)
    findings = get_findings_for_contract(con, contract_id)
    return {"contract": contract, "findings": findings}