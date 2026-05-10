"""Custom heuristic detectors and confidence scoring.

Closes Phase 1.4 of the roadmap. These detectors are pure-Python regex/string
heuristics over Solidity source — they don't replace Slither, they augment it
when Slither isn't installed (common in demo/CI environments) and they cover
patterns Slither doesn't ship with by default (e.g. UUPS upgrade gates,
single-source oracle reads, missing _disableInitializers).

Confidence scoring is a deterministic blend of:

    - severity weight (High > Medium > Low > Informational)
    - provenance weight (curated_seed / postmortem > static_analysis > heuristic)
    - corroboration: a finding's class repeating across detectors on the same
      contract gets a small bump.

The score is in [0.0, 1.0]. It lives in a new ``findings.confidence_score``
column and is re-derivable; the recompute helper is idempotent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import duckdb

from backend.db_enhanced import classify_detector, insert_finding


# ---------------------------------------------------------------------------
# Heuristic detectors
# ---------------------------------------------------------------------------

@dataclass
class HeuristicFinding:
    detector: str
    severity: str
    confidence: str
    description: str


# Each detector takes the joined source text and returns a list of findings.
# Keep them deliberately conservative — false positives are worse than misses
# in a public dataset.

_RE_INITIALIZE_NO_DISABLE = re.compile(
    r"function\s+initialize\s*\(", re.IGNORECASE
)
_RE_DISABLE_INITIALIZERS = re.compile(
    r"_disableInitializers\s*\(", re.IGNORECASE
)
_RE_INITIALIZER_MODIFIER = re.compile(r"\binitializer\b")
_RE_TX_ORIGIN = re.compile(r"tx\s*\.\s*origin")
_RE_DELEGATECALL = re.compile(r"\.\s*delegatecall\s*\(")
_RE_SELFDESTRUCT = re.compile(r"\b(selfdestruct|suicide)\s*\(")
_RE_SINGLE_ORACLE = re.compile(
    r"(getReserves|latestAnswer|latestRoundData|price0CumulativeLast|price1CumulativeLast)\s*\("
)
_RE_BLOCK_TIMESTAMP = re.compile(r"block\s*\.\s*timestamp")
_RE_ECRECOVER = re.compile(r"\becrecover\s*\(")
_RE_NONCE_OR_REPLAY = re.compile(r"\b(nonce|usedSignature|usedHash)\b", re.IGNORECASE)
_RE_OWNER_TRANSFER = re.compile(r"transferOwnership\s*\(")
_RE_OWNER_TWO_STEP = re.compile(
    r"(pendingOwner|acceptOwnership|claimOwnership|Ownable2Step)", re.IGNORECASE
)
_RE_OPENZEPPELIN_NONREENTRANT = re.compile(r"\bnonReentrant\b")
_RE_LOW_LEVEL_CALL = re.compile(r"\.\s*call\s*\{")


def _detector_uups_initializer(src: str) -> list[HeuristicFinding]:
    if not _RE_INITIALIZE_NO_DISABLE.search(src):
        return []
    out: list[HeuristicFinding] = []
    if not _RE_DISABLE_INITIALIZERS.search(src):
        out.append(HeuristicFinding(
            detector="missing-disable-initializers",
            severity="High",
            confidence="Medium",
            description=(
                "Upgradeable contract exposes initialize() but the constructor does "
                "not call _disableInitializers(). The implementation contract itself "
                "remains initializable, allowing an attacker to take it over and "
                "(via UUPSUpgradeable) self-upgrade, bricking or hijacking the proxy."
            ),
        ))
    if not _RE_INITIALIZER_MODIFIER.search(src):
        out.append(HeuristicFinding(
            detector="initialize-without-modifier",
            severity="High",
            confidence="Medium",
            description=(
                "initialize() does not appear to be guarded by an `initializer` "
                "modifier. Without it, the function can be called repeatedly to "
                "reset privileged state (Wormhole-style hazard)."
            ),
        ))
    return out


def _detector_tx_origin(src: str) -> list[HeuristicFinding]:
    if not _RE_TX_ORIGIN.search(src):
        return []
    return [HeuristicFinding(
        detector="tx-origin",
        severity="Medium",
        confidence="High",
        description=(
            "Use of tx.origin in privileged path. EOAs interacting with malicious "
            "contracts are vulnerable to phishing — prefer msg.sender."
        ),
    )]


def _detector_delegatecall(src: str) -> list[HeuristicFinding]:
    if not _RE_DELEGATECALL.search(src):
        return []
    return [HeuristicFinding(
        detector="controlled-delegatecall",
        severity="High",
        confidence="Medium",
        description=(
            "delegatecall present. If the target address is caller-controlled "
            "or the implementation slot is mutable without a timelock, this is a "
            "direct-drain primitive (Parity Multisig pattern)."
        ),
    )]


def _detector_selfdestruct(src: str) -> list[HeuristicFinding]:
    if not _RE_SELFDESTRUCT.search(src):
        return []
    return [HeuristicFinding(
        detector="suicidal",
        severity="High",
        confidence="High",
        description=(
            "selfdestruct/suicide in code path. If reachable by an unprivileged "
            "caller, the contract can be deleted; if it backs a delegatecall "
            "library, all dependent contracts are bricked (Parity Wallet 2017)."
        ),
    )]


def _detector_single_source_oracle(src: str) -> list[HeuristicFinding]:
    if not _RE_SINGLE_ORACLE.search(src):
        return []
    has_twap = "TWAP" in src.upper() or "cumulativeLast" in src
    if has_twap:
        return []
    return [HeuristicFinding(
        detector="single-source-oracle",
        severity="Medium",
        confidence="Medium",
        description=(
            "Spot price read from a single source (Uniswap getReserves / "
            "Chainlink latestAnswer) without TWAP smoothing or staleness check. "
            "Recurring root cause across bZx, Mango, Cream, Inverse Finance."
        ),
    )]


def _detector_signature_replay(src: str) -> list[HeuristicFinding]:
    if not _RE_ECRECOVER.search(src):
        return []
    if _RE_NONCE_OR_REPLAY.search(src):
        return []
    return [HeuristicFinding(
        detector="signature-replay",
        severity="High",
        confidence="Medium",
        description=(
            "ecrecover() is used but no nonce/usedSignature mapping is visible. "
            "Signed messages can be replayed against the same contract or across "
            "chains if chainId is not bound (LoopFi-style hazard)."
        ),
    )]


def _detector_two_step_ownership(src: str) -> list[HeuristicFinding]:
    if not _RE_OWNER_TRANSFER.search(src):
        return []
    if _RE_OWNER_TWO_STEP.search(src):
        return []
    return [HeuristicFinding(
        detector="missing-two-step-ownership",
        severity="High",
        confidence="High",
        description=(
            "transferOwnership without a pending/accept two-step pattern. A single "
            "compromised signature (Radiant Capital 2024) hands over the contract "
            "instantly; a two-step pattern would have required a second signed "
            "tx from the destination address."
        ),
    )]


def _detector_low_level_call(src: str) -> list[HeuristicFinding]:
    if not _RE_LOW_LEVEL_CALL.search(src):
        return []
    return [HeuristicFinding(
        detector="unchecked-lowlevel",
        severity="Low",
        confidence="Medium",
        description=(
            "Low-level .call{...}() present. Confirm return value is checked and "
            "that called targets are allowlisted to avoid arbitrary external "
            "interaction."
        ),
    )]


HEURISTICS = [
    _detector_uups_initializer,
    _detector_tx_origin,
    _detector_delegatecall,
    _detector_selfdestruct,
    _detector_single_source_oracle,
    _detector_signature_replay,
    _detector_two_step_ownership,
    _detector_low_level_call,
]


def run_heuristics(sources: dict | str) -> list[HeuristicFinding]:
    """Run all heuristic detectors on Solidity sources.

    Args:
        sources: either a single source string, a dict {path: code}, or
            a dict {path: {"content": "..."}}.

    Returns:
        list of HeuristicFinding (deduped by detector).
    """
    if isinstance(sources, str):
        joined = sources
    else:
        parts: list[str] = []
        for filepath, val in sources.items():
            if not filepath.endswith((".sol", ".vy")):
                continue
            content = val["content"] if isinstance(val, dict) else val
            parts.append(content or "")
        joined = "\n".join(parts)

    seen: set[str] = set()
    out: list[HeuristicFinding] = []
    for det in HEURISTICS:
        for f in det(joined):
            if f.detector in seen:
                continue
            seen.add(f.detector)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT = {
    "High": 0.45,
    "Medium": 0.30,
    "Low": 0.18,
    "Informational": 0.08,
    "Optimization": 0.05,
}

_CONFIDENCE_WEIGHT = {
    "High": 0.30,
    "Medium": 0.20,
    "Low": 0.10,
    None: 0.10,
}

_PROVENANCE_WEIGHT = {
    "incident_postmortem": 0.25,
    "curated_seed": 0.20,
    "audit": 0.20,
    "datamine_fallback": 0.12,
    "static_analysis": 0.15,
    "heuristic": 0.10,
    "synthetic_augmentation": 0.05,
}


def score_finding(
    severity: str | None,
    confidence: str | None,
    provenance: str | None,
    sibling_count: int = 0,
) -> float:
    """Return a 0..1 confidence score for a single finding.

    sibling_count: number of *other* findings on the same contract sharing the
    same vulnerability_class. A non-zero value gives a small corroboration
    bump (capped at +0.10) so multiple detectors agreeing reinforces the call.
    """
    base = (
        _SEVERITY_WEIGHT.get(severity or "", 0.08)
        + _CONFIDENCE_WEIGHT.get(confidence, 0.10)
        + _PROVENANCE_WEIGHT.get(provenance or "static_analysis", 0.10)
    )
    bump = min(0.10, sibling_count * 0.03)
    return round(min(1.0, base + bump), 3)


def ensure_confidence_score_column(con: duckdb.DuckDBPyConnection) -> None:
    """Add findings.confidence_score if missing."""
    con.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS confidence_score DOUBLE"
    )


def recompute_confidence_scores(con: duckdb.DuckDBPyConnection) -> int:
    """Recompute confidence_score for every finding. Returns rows updated."""
    ensure_confidence_score_column(con)
    rows = con.execute(
        """
        SELECT f.id, f.severity, f.confidence, f.provenance,
               f.contract_id, f.vulnerability_class
        FROM findings f
        """
    ).fetchall()
    if not rows:
        return 0

    # Pre-compute sibling counts per (contract_id, vulnerability_class).
    sib = {}
    for _id, _sev, _conf, _prov, cid, vc in rows:
        if vc is None or cid is None:
            continue
        sib[(cid, vc)] = sib.get((cid, vc), 0) + 1

    updates = 0
    for fid, sev, conf, prov, cid, vc in rows:
        siblings = max(0, sib.get((cid, vc), 1) - 1)
        score = score_finding(sev, conf, prov, sibling_count=siblings)
        con.execute(
            "UPDATE findings SET confidence_score = ? WHERE id = ?",
            [score, fid],
        )
        updates += 1
    return updates


def insert_heuristic_findings(
    con: duckdb.DuckDBPyConnection,
    contract_id: int,
    sources: dict | str,
) -> int:
    """Run heuristics on sources and insert findings (deduped). Returns count."""
    findings = run_heuristics(sources)
    inserted = 0
    for f in findings:
        # Skip if already present.
        existing = con.execute(
            "SELECT id FROM findings WHERE contract_id = ? AND detector = ?",
            [contract_id, f.detector],
        ).fetchone()
        if existing:
            continue
        tax = classify_detector(f.detector)
        insert_finding(
            con,
            contract_id=contract_id,
            detector=f.detector,
            severity=f.severity,
            confidence=f.confidence,
            description=f.description,
            vulnerability_class=tax["vulnerability_class"],
            layer=tax["layer"],
            exploitability=tax["exploitability"],
            provenance="heuristic",
            reproducibility="static-only",
        )
        inserted += 1
    return inserted


def aggregate_contract_score(con: duckdb.DuckDBPyConnection, contract_id: int) -> dict:
    """Return aggregate risk profile for a contract.

    {
      "score": 0..1 (max of finding scores, weighted by recurrence),
      "high_count": int,
      "medium_count": int,
      "low_count": int,
      "classes": [class names, distinct],
      "top_finding": {detector, severity, score, ...} | None
    }
    """
    rows = con.execute(
        """
        SELECT id, detector, severity, vulnerability_class, confidence_score
        FROM findings
        WHERE contract_id = ?
        ORDER BY COALESCE(confidence_score, 0) DESC
        """,
        [contract_id],
    ).fetchall()
    if not rows:
        return {
            "score": 0.0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "classes": [],
            "top_finding": None,
        }
    classes: list[str] = []
    high = medium = low = 0
    top = None
    max_score = 0.0
    for _id, det, sev, vc, sc in rows:
        if vc and vc not in classes:
            classes.append(vc)
        if sev == "High":
            high += 1
        elif sev == "Medium":
            medium += 1
        elif sev == "Low":
            low += 1
        s = float(sc or 0)
        if s > max_score:
            max_score = s
        if top is None:
            top = {"id": _id, "detector": det, "severity": sev, "score": s}
    return {
        "score": round(max_score, 3),
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "classes": classes,
        "top_finding": top,
    }
