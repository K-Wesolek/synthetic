"""Datamine the Sourcify dataset for additional verified contracts.

This script walks a curated list of (chain_id, address, contract_name,
fallback_findings) tuples and:

1. Calls the Sourcify v2 API to fetch verified source + metadata.
2. Runs the existing ingest pipeline (`ingest_enhanced.ingest_contract`) so
   compiler settings, storage layout and ABI are persisted.
3. If Slither is unavailable or returns nothing, attaches the curated
   fallback findings so the demo dataset always has something to show.

It is **idempotent** — `ingest_contract` already deduplicates on
(chain_id, address) and on source_code_hash, so re-running this script does
not double-count anything.

Run:
    python3 -m backend.datamine

Pass ``--limit N`` to process only the first N entries (useful while
developing). Pass ``--no-network`` to skip Sourcify and only insert curated
contract stubs + findings (offline / demo mode).
"""
from __future__ import annotations

import argparse
import sys
import time
from typing import Iterable

import requests

from backend.db_enhanced import (
    classify_detector,
    get_connection,
    get_contract,
    init_db,
    insert_contract,
    insert_finding,
)
from backend.ingest_enhanced import ingest_contract


# ---------------------------------------------------------------------------
# Curated list of historically-vulnerable verified contracts.
#
# Each entry MUST include:
#   - chain_id, address: the Sourcify lookup key
#   - name: a fallback name when Sourcify hasn't seen it
#   - reason: short note about why it's interesting (post-mortem source etc.)
#   - findings: curated fallback findings (used when Slither yields nothing).
# ---------------------------------------------------------------------------

MINING_TARGETS: list[dict] = [
    {
        "chain_id": "1",
        "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC v1
        "name": "USDC",
        "reason": "Stablecoin with admin-controlled mint/freeze surfaces, common reference contract for governance-risk reviews.",
        "findings": [
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "USDC.masterMinter / pauser / blacklister roles are admin-only. Single multisig key compromise can freeze all transfers."},
            {"detector": "upgradeability-flaw", "severity": "Low", "confidence": "Medium",
             "description": "Upgradable proxy under Centre admin. Downstream integrators must monitor implementation upgrades."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH9
        "name": "WrappedEther",
        "reason": "Canonical WETH9. Used to demonstrate clean baseline & integration-layer risks.",
        "findings": [
            {"detector": "missing-zero-check", "severity": "Informational", "confidence": "Medium",
             "description": "WETH9 deposit/withdraw lacks contract-receive checks; integrators using send() with low gas may revert."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0xa0b73e1ff0b80914ab6fe0444e65848c4c34450b",  # Cronos / cRO bridge - placeholder
        "name": "GenericBridgeProxy",
        "reason": "Common bridge proxy pattern — initialization & upgrade hazards.",
        "findings": [
            {"detector": "uninitialized-state", "severity": "High", "confidence": "Medium",
             "description": "Proxy initialize() callable when implementation already initialised on a separate chain — replay risk."},
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "Bridge admin can pause / set new implementation; single-key compromise drains escrow."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0x1985365e9f78359a9b6ad760e32412f4a445e862",  # REP v1 (Augur)
        "name": "ReputationToken",
        "reason": "Early ERC20 with non-standard return semantics — classic integration-layer hazard.",
        "findings": [
            {"detector": "unchecked-transfer", "severity": "Medium", "confidence": "High",
             "description": "transfer() reverts instead of returning false on failure; integrators that check return values will misinterpret."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Compiled with 0.4.x; recompile under 0.8.x for default overflow checks."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0xb8c77482e45f1f44de1745f52c74426c631bdd52",  # BNB
        "name": "BinanceCoin",
        "reason": "BEP-2 era ERC20 wrapper — owner-controlled supply.",
        "findings": [
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "owner can mint/freeze tokens; single-key risk."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",  # Lido stETH
        "name": "Lido_stETH",
        "reason": "Liquid staking token; rebase mechanics interact with DeFi accounting bugs.",
        "findings": [
            {"detector": "accounting-rebase", "severity": "Medium", "confidence": "High",
             "description": "stETH share <-> balance rounding mismatches surface accounting bugs in protocols that assume static balances (e.g. Penpie, Aave v2 LST flash drops)."},
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "Oracle/quorum committee controls reportBeacon. Compromise could mis-report rebase factor."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave v2 LendingPool
        "name": "AaveLendingPoolV2",
        "reason": "Reference DeFi lending pool used in many forks and exploits.",
        "findings": [
            {"detector": "oracle-dependence", "severity": "Medium", "confidence": "High",
             "description": "Liquidations depend on Chainlink oracles; thin-feed assets (e.g. Mango-style listings) are the recurring risk."},
            {"detector": "reentrancy-no-eth", "severity": "Low", "confidence": "Medium",
             "description": "Read-only reentrancy possible via aToken hooks if integrators don't pin index."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0x57ab1ec28d129707052df4df418d58a2d46d5f51",  # sUSD
        "name": "SynthetixSUSD",
        "reason": "Token with delegation + multisig owner; touchpoint for Synthetix oracle history.",
        "findings": [
            {"detector": "tx-origin", "severity": "Medium", "confidence": "Medium",
             "description": "Legacy auth path used tx.origin in some forks — phishing risk if callers are EOAs."},
        ],
    },
    {
        "chain_id": "1",
        "address": "0x3506424f91fd33084466f402d5d97f05f8e3b4af",  # Chiliz CHZ (random ERC20)
        "name": "ChilizToken",
        "reason": "Plain ERC20 baseline for compiler-distribution stats.",
        "findings": [],
    },
    {
        "chain_id": "10",  # Optimism
        "address": "0x4200000000000000000000000000000000000010",
        "name": "OptimismL1StandardBridge",
        "reason": "L2 standard bridge — initialization & message-replay surface.",
        "findings": [
            {"detector": "upgradeability-flaw", "severity": "Medium", "confidence": "High",
             "description": "Cross-domain message replay if nonce/finality assumptions are wrong (Nomad/cBridge category)."},
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "Upgrade admin holds emergency power; multisig key compromise = drain."},
        ],
    },
    {
        "chain_id": "42161",  # Arbitrum
        "address": "0x5979d7b546e38e414f7e9822514be443a4800529",
        "name": "wstETH_Arbitrum",
        "reason": "L2 LST bridge — share/rate cache bugs propagate across chains.",
        "findings": [
            {"detector": "oracle-dependence", "severity": "Medium", "confidence": "High",
             "description": "Cross-chain rate provider must be pinned; stale rate -> oracle-manipulation profile."},
        ],
    },
    {
        "chain_id": "8453",  # Base
        "address": "0x4200000000000000000000000000000000000006",  # WETH on Base
        "name": "Base_WETH",
        "reason": "Predeploy WETH on Base, baseline compiler-config datapoint.",
        "findings": [],
    },
    # --- Known hack victims from the curated incidents list ---
    {
        "chain_id": "1",
        "address": "0x27182842E098f60e3D576794A5bFFb0777E025d3",
        "name": "EulerProtocol",
        "reason": "Euler Finance — March 2023 donateToReserves bug, $197M drain.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B",
        "name": "CompoundComptroller",
        "reason": "Compound governance — comp distribution bug 2021, ~$80M, COMP overpay.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0xc6D32E11ec5C9F09FFa2C50f7cC7D7e02e89e15A",
        "name": "WormholeBridge",
        "reason": "Wormhole core bridge — Feb 2022 signature verification bypass, $326M.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x88128fd4b259552A9A1D457f435a6527AAb72d42",
        "name": "MakerDAO_DAI",
        "reason": "Reference stablecoin issuer / governance.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0xe592427a0aece92de3edee1f18e0157c05861564",
        "name": "UniswapV3Router",
        "reason": "Uniswap V3 router — frequently integrated; callback-reentrancy surface.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
        "name": "UniswapV2Factory",
        "reason": "Uniswap V2 factory — pair model used by countless forks.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0xD1669Ac6044269b59Fa12c5822439F609Ca54F41",
        "name": "ConvexBooster",
        "reason": "Convex booster — Curve LP wrapping, frequent oracle-dependence target.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x2F0b23f53734252Bda2277357e97e1517d6B042A",
        "name": "GnosisMultisig",
        "reason": "Gnosis multisig — used everywhere, common privilege-escalation target.",
        "findings": [],
    },
    {
        "chain_id": "56",  # BSC
        "address": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
        "name": "PancakeSwapRouterV2",
        "reason": "PancakeSwap V2 — most-forked AMM router on BSC.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52",
        "name": "YearnLockedDai",
        "reason": "Yearn vault — Feb 2021 yDAI v1 misprice exploit, $11M.",
        "findings": [],
    },
    {
        "chain_id": "137",  # Polygon
        "address": "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
        "name": "WMATIC",
        "reason": "Polygon wrapped native — baseline cross-chain reference.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0xa0b73e1Ff0B80914AB6fE0444E65848C4C34450b",
        "name": "CronosBridge",
        "reason": "Cronos bridge — initialization-flaw category.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x7c5621dfC72D9956458Df37b6a3a52e8b0e0F2fE",
        "name": "BadgerDAO_Vault",
        "reason": "Badger DAO — Dec 2021 frontend phishing wrapped via approvals, $120M.",
        "findings": [],
    },
    {
        "chain_id": "1",
        "address": "0x3A23F943181408EAC424116Af7b7790c94Cb97a5",
        "name": "Socket_Gateway",
        "reason": "Socket bridge gateway — Jan 2024 approval drain via uninitialised route, $3.3M.",
        "findings": [],
    },
]


def _attach_fallback_findings(con, contract_id: int, findings: Iterable[dict]) -> int:
    """Insert curated fallback findings for a contract, deduping on description."""
    inserted = 0
    for finding in findings:
        existing = con.execute(
            "SELECT id FROM findings WHERE contract_id = ? AND detector = ? AND description = ?",
            [contract_id, finding["detector"], finding["description"]],
        ).fetchone()
        if existing:
            continue
        tax = classify_detector(finding["detector"])
        insert_finding(
            con,
            contract_id=contract_id,
            detector=finding["detector"],
            severity=finding["severity"],
            confidence=finding.get("confidence"),
            description=finding["description"],
            vulnerability_class=tax["vulnerability_class"],
            layer=tax["layer"],
            exploitability=tax["exploitability"],
            provenance="datamine_fallback",
            reproducibility="report-only",
        )
        inserted += 1
    return inserted


def _ingest_one(con, target: dict, network: bool, run_slither: bool) -> dict:
    chain_id = target["chain_id"]
    address = target["address"]
    name = target["name"]
    fallback = target.get("findings", [])

    existing = get_contract(con, chain_id, address)
    if existing is not None:
        added = _attach_fallback_findings(con, existing["id"], fallback)
        return {"address": address, "status": "exists", "added_findings": added}

    if network:
        try:
            result = ingest_contract(
                con, chain_id, address, run_slither=run_slither
            )
            cid = result["contract"]["id"]
            added_fallback = 0
            if not result["findings"]:
                added_fallback = _attach_fallback_findings(con, cid, fallback)
            return {
                "address": address,
                "status": "ingested",
                "slither_findings": len(result["findings"]),
                "fallback_findings": added_fallback,
            }
        except requests.RequestException as exc:
            # Sourcify miss / network error — fall back to a stub contract +
            # curated findings so the demo still has data.
            err = str(exc).split("\n", 1)[0][:200]
            cid = insert_contract(
                con,
                address=address,
                chain_id=chain_id,
                contract_name=name,
                compiler_version="unknown",
                language="Solidity",
                optimizer_enabled=None,
                optimizer_runs=None,
            )
            added = _attach_fallback_findings(con, cid, fallback)
            return {
                "address": address,
                "status": "stub_after_network_error",
                "error": err,
                "added_findings": added,
            }
    else:
        cid = insert_contract(
            con,
            address=address,
            chain_id=chain_id,
            contract_name=name,
            compiler_version="unknown",
            language="Solidity",
            optimizer_enabled=None,
            optimizer_runs=None,
        )
        added = _attach_fallback_findings(con, cid, fallback)
        return {"address": address, "status": "stub_offline", "added_findings": added}


def datamine(
    limit: int | None = None,
    network: bool = True,
    run_slither: bool = False,
    sleep_s: float = 0.5,
    con: "duckdb.DuckDBPyConnection | None" = None,
) -> list[dict]:
    """Run the miner and return per-target outcomes.

    Pass an existing ``con`` to reuse an open DuckDB connection (e.g. when the
    FastAPI app is holding the writer lock). Otherwise a fresh one is opened.
    """
    owns_conn = con is None
    if owns_conn:
        con = get_connection()
    init_db(con)

    targets = MINING_TARGETS[:limit] if limit else MINING_TARGETS
    out: list[dict] = []
    for i, t in enumerate(targets, 1):
        try:
            res = _ingest_one(con, t, network=network, run_slither=run_slither)
        except Exception as exc:  # robust: never abort the whole run
            res = {"address": t["address"], "status": "error", "error": str(exc)[:200]}
        print(f"[{i}/{len(targets)}] {t['chain_id']}:{t['address']} -> {res.get('status')}", flush=True)
        out.append(res)
        if network and sleep_s:
            time.sleep(sleep_s)  # be polite to Sourcify

    contracts_n = con.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
    findings_n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    print(f"DB now: {contracts_n} contracts, {findings_n} findings")
    if owns_conn:
        con.close()
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Datamine Sourcify into the Atlas DB.")
    parser.add_argument("--limit", type=int, default=None, help="process only first N targets")
    parser.add_argument("--no-network", action="store_true", help="skip Sourcify (insert stubs)")
    parser.add_argument("--slither", action="store_true", help="run Slither on each (slow)")
    args = parser.parse_args(argv)

    datamine(
        limit=args.limit,
        network=not args.no_network,
        run_slither=args.slither,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
