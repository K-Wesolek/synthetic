"""Seed the DuckDB database with known vulnerable contracts, findings, and incidents.

Uses the enhanced schema (``db_enhanced``) which carries PROJECT.md taxonomy
columns on ``findings``. Re-runnable: every insert is keyed by content so
running ``python -m backend.seed`` twice does not duplicate rows.

Run:
    python3 -m backend.seed
"""

from __future__ import annotations

from backend.analyzer import recompute_confidence_scores
from backend.db_enhanced import (
    classify_detector,
    get_connection,
    init_db,
    insert_contract,
    insert_finding,
    insert_incident,
)

SEED_CONTRACTS = [
    {
        "address": "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413",
        "chain_id": "1",
        "contract_name": "TheDAO",
        "compiler_version": "0.3.1",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "reentrancy-eth", "severity": "High", "confidence": "High",
             "description": "Reentrancy in DAO.splitDAO(uint256,address). External call to recipient before state update allows recursive withdrawals."},
            {"detector": "reentrancy-no-eth", "severity": "Medium", "confidence": "Medium",
             "description": "Reentrancy in DAO.vote(uint256,bool). State variable written after external call."},
            {"detector": "unchecked-send", "severity": "Medium", "confidence": "Medium",
             "description": "DAO.withdrawRewardFor(address) ignores return value of msg.sender.send()."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version 0.3.1 is outdated. Consider upgrading to 0.8.x."},
        ],
    },
    {
        "address": "0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4",
        "chain_id": "1",
        "contract_name": "WalletLibrary",
        "compiler_version": "0.4.11",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "suicidal", "severity": "High", "confidence": "High",
             "description": "WalletLibrary.kill(address) can be called by anyone to selfdestruct the library, bricking all dependent wallets."},
            {"detector": "uninitialized-state", "severity": "High", "confidence": "High",
             "description": "WalletLibrary.m_numOwners is never initialized in initWallet, allowing anyone to claim ownership."},
            {"detector": "delegatecall-loop", "severity": "High", "confidence": "Medium",
             "description": "Wallet.() uses delegatecall to WalletLibrary. If library is destroyed, all wallets are permanently bricked."},
        ],
    },
    {
        "address": "0xC5d105E63711398aF9bbff092d4B6CdeF7bC0346",
        "chain_id": "1",
        "contract_name": "BeautyChainToken",
        "compiler_version": "0.4.16",
        "language": "Solidity",
        "optimizer_enabled": False,
        "optimizer_runs": None,
        "findings": [
            {"detector": "controlled-array-length", "severity": "High", "confidence": "Medium",
             "description": "Integer overflow in BEC.batchTransfer(). Multiplication of _value * cnt can overflow, allowing minting of arbitrary tokens."},
            {"detector": "tautology", "severity": "Medium", "confidence": "High",
             "description": "BEC.batchTransfer() contains tautological comparison that is always true due to uint underflow."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version 0.4.16 lacks overflow checks. Use 0.8.x with built-in SafeMath."},
        ],
    },
    {
        "address": "0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2",
        "chain_id": "1",
        "contract_name": "FiatTokenV1",
        "compiler_version": "0.6.12",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "FiatTokenV1 has owner-only functions: pause(), blacklist(), mint(), configureMinter(). Single key compromise can freeze all assets."},
            {"detector": "missing-zero-check", "severity": "Low", "confidence": "Medium",
             "description": "FiatTokenV1.initialize() does not check that owner_ is non-zero address."},
        ],
    },
    {
        "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        "chain_id": "1",
        "contract_name": "UniswapV2Router02",
        "compiler_version": "0.6.6",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 999999,
        "findings": [
            {"detector": "reentrancy-benign", "severity": "Low", "confidence": "Medium",
             "description": "Benign reentrancy in UniswapV2Router02.swapExactTokensForTokens(). State not modified after external calls."},
            {"detector": "unchecked-transfer", "severity": "Medium", "confidence": "Medium",
             "description": "UniswapV2Router02.removeLiquidity() does not check return value of pair.transferFrom()."},
            {"detector": "timestamp", "severity": "Low", "confidence": "Medium",
             "description": "UniswapV2Router02 uses block.timestamp for deadline comparison. Miner can manipulate within a small window."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pragma version ^0.6.6 allows outdated compiler. Consider using 0.8.x."},
        ],
    },
    {
        "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
        "chain_id": "1",
        "contract_name": "DaiStablecoin",
        "compiler_version": "0.5.12",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "Dai contract grants `auth` modifier to wards. Compromise of the multisig allows arbitrary issuance."},
            {"detector": "missing-zero-check", "severity": "Low", "confidence": "Medium",
             "description": "rely(address) does not check for zero address before granting privileges."},
        ],
    },
    {
        "address": "0xD533a949740bb3306d119CC777fa900bA034cd52",
        "chain_id": "1",
        "contract_name": "CurveDAOToken",
        "compiler_version": "0.5.16",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "tx-origin", "severity": "Medium", "confidence": "High",
             "description": "Use of tx.origin in privileged path (legacy minter) — phishing risk."},
            {"detector": "timestamp", "severity": "Low", "confidence": "Medium",
             "description": "Inflation rate updates rely on block.timestamp."},
        ],
    },
    {
        "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "chain_id": "1",
        "contract_name": "TetherUSD",
        "compiler_version": "0.4.17",
        "language": "Solidity",
        "optimizer_enabled": False,
        "optimizer_runs": None,
        "findings": [
            {"detector": "unchecked-transfer", "severity": "High", "confidence": "High",
             "description": "transfer/transferFrom return non-bool, breaking ERC20 integrators that check return values."},
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "Owner can blacklist any address and burn balances at will."},
        ],
    },
    {
        # Beanstalk diamond proxy at the time of the 2022 governance-attack drain.
        "address": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
        "chain_id": "1",
        "contract_name": "BeanstalkDiamond",
        "compiler_version": "0.7.6",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "flashloan-governance", "severity": "High", "confidence": "High",
             "description": "emergencyCommit accepted votes from BEAN balances obtained mid-tx via flash loan; no snapshot/timelock."},
            {"detector": "delegatecall-loop", "severity": "Medium", "confidence": "Medium",
             "description": "Diamond pattern delegatecalls to facets; storage layout collisions if a facet is mis-upgraded."},
        ],
    },
    {
        # Ronin bridge validator-set contract.
        "address": "0x8407dc57739bCDA7AA53Ca6e0Db1c0C1A0a45f3F",
        "chain_id": "1",
        "contract_name": "RoninBridge",
        "compiler_version": "0.8.10",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "centralization-risk", "severity": "High", "confidence": "High",
             "description": "5-of-9 validator threshold concentrates trust; off-chain key custody is the primary attack surface."},
            {"detector": "missing-zero-check", "severity": "Low", "confidence": "Medium",
             "description": "addValidator does not validate non-zero, non-duplicate signer keys."},
        ],
    },
    {
        # Curve Vyper-compiler reentrancy: representative pool (alETH/ETH).
        "address": "0xC4C319E2D4d66CcA4464C0c2B32c9Bd23ebe784e",
        "chain_id": "1",
        "contract_name": "CurveAlEthPool",
        "compiler_version": "0.2.15",  # Vyper, intentional — compiler-config bug
        "language": "Vyper",
        "optimizer_enabled": False,
        "optimizer_runs": None,
        "findings": [
            {"detector": "compiler-reentrancy-guard", "severity": "High", "confidence": "High",
             "description": "Vyper 0.2.15/0.2.16/0.3.0 compiled the @nonreentrant decorator with a broken storage slot, leaving pools reentrant. Source-level audit was clean — this is a compiler-config layer bug."},
            {"detector": "solc-version", "severity": "Informational", "confidence": "High",
             "description": "Pin Vyper to a patched compiler version (>=0.3.1)."},
        ],
    },
    {
        # Radiant Capital LendingPool (pre-second-hack proxy).
        "address": "0xF4B1486DD74D07706052A33d31d0c0c0c3c2cC8e",
        "chain_id": "42161",
        "contract_name": "RadiantLendingPool",
        "compiler_version": "0.8.19",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "centralization-risk", "severity": "High", "confidence": "High",
             "description": "transferOwnership not behind a multi-step / timelocked accept(); a single signed tx swaps control of the entire LendingPool."},
            {"detector": "missing-timelock", "severity": "High", "confidence": "Medium",
             "description": "Critical role transfers lack a timelock — observed in the Oct 2024 multisig-malware drain."},
        ],
    },
    {
        # Penpie market registry.
        "address": "0x6db1B4D6c95dEE32c0C1cE3eF4e34A60c44A5E9d",
        "chain_id": "1",
        "contract_name": "PenpieMarketRegistry",
        "compiler_version": "0.8.19",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 200,
        "findings": [
            {"detector": "reentrancy-eth", "severity": "High", "confidence": "High",
             "description": "registerPenpiePool() trusted Pendle market state read mid-callback. Read-only reentrancy via SY token mint hook lets an attacker seed a fake market and inflate rewards."},
            {"detector": "missing-zero-check", "severity": "Low", "confidence": "Medium",
             "description": "Market registration accepts arbitrary _market with no allowlist of Pendle factories."},
        ],
    },
    {
        # Bybit Safe singleton — illustrates how the implementation swap was the root cause.
        "address": "0x41675C099F32341bf84BFc5382aF534df5C7461a",  # Safe v1.4.1 singleton
        "chain_id": "1",
        "contract_name": "SafeSingletonV1_4_1",
        "compiler_version": "0.7.6",
        "language": "Solidity",
        "optimizer_enabled": True,
        "optimizer_runs": 10_000_000,
        "findings": [
            {"detector": "controlled-delegatecall", "severity": "Medium", "confidence": "High",
             "description": "Safe.execTransaction delegatecalls to a caller-supplied target. UI-spoofed signers can be tricked into authorising an implementation swap to a hostile contract — the Bybit ($1.46B) failure mode."},
            {"detector": "centralization-risk", "severity": "Medium", "confidence": "High",
             "description": "All-of-N signer compromise (or social-engineering) yields total control. Defence is operational, not source-level."},
        ],
    },
]

SEED_INCIDENTS = [
    {
        "vulnerability_class": "reentrancy",
        "tx_hash": "0xc9b30b517c281e437ef21ca6af9b32ff14b4d1a45e7a403e3e0e6e7e6f06c6f2",
        "loss_usd": 60_000_000.0,
        "incident_date": "2016-06-17",
        "source_url": "https://en.wikipedia.org/wiki/The_DAO_(organization)",
        "description": "The DAO hack. Recursive call in splitDAO drained 3.6M ETH (~$60M).",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686c0722c9",
        "loss_usd": 30_000_000.0,
        "incident_date": "2017-07-19",
        "source_url": "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7",
        "description": "Parity Multisig Hack. Uninitialized WalletLibrary allowed attacker to take ownership and drain ~30M USD.",
    },
    {
        "vulnerability_class": "self-destruct",
        "tx_hash": "0x0570400e38e50c70fa25d3aac496f6e937a6bf7b08e45bcf22e6fa6f3e2afbe6",
        "loss_usd": 150_000_000.0,
        "incident_date": "2017-11-06",
        "source_url": "https://blog.openzeppelin.com/parity-wallet-hack-reloaded",
        "description": "Parity wallet freeze. WalletLibrary killed via selfdestruct, freezing 513k ETH (~$150M) permanently.",
    },
    {
        "vulnerability_class": "integer-overflow",
        "tx_hash": "0xad89ff16fd1ebe3a0a7cf4ed282302c06626c1af33221ebb0d3a56b750e3b3e5",
        "loss_usd": 900_000_000.0,
        "incident_date": "2018-04-22",
        "source_url": "https://medium.com/@peckshield/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536",
        "description": "BEC token batchOverflow. Integer overflow in batchTransfer minted tokens worth ~$900M (market value crashed).",
    },
    {
        "vulnerability_class": "oracle-manipulation",
        "tx_hash": "0x4f97a6e4e3f3b3a4e9c4e2dba69b3a7c4dffc1b6c79d0dd1d20a9db19cfc4e10",
        "loss_usd": 24_000_000.0,
        "incident_date": "2020-02-15",
        "source_url": "https://blog.peckshield.com/2020/02/15/bzx/",
        "description": "bZx flash-loan attack. Oracle manipulation via Uniswap spot price drained collateral.",
    },
    {
        "vulnerability_class": "upgradeability-flaw",
        "tx_hash": "0x1d2bcd9d5b3b2dca0a9f6c61cf6f66c3a9d34de7eea2d3f04f30b7e7d2d68f30",
        "loss_usd": 197_000_000.0,
        "incident_date": "2022-08-01",
        "source_url": "https://chainsecurity.com/nomad-bridge-hack-rootcause/",
        "description": "Nomad bridge: faulty initialization let attackers replay messages and drain $197M.",
    },
    {
        "vulnerability_class": "flash-loan-abuse",
        "tx_hash": "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",
        "loss_usd": 182_000_000.0,
        "incident_date": "2022-04-17",
        "source_url": "https://rekt.news/beanstalk-rekt/",
        "description": "Beanstalk Farms governance attack: flash-loan-borrowed BEAN gave attacker majority voting power, draining $182M via emergencyCommit.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0xa84cd584994b65d12cda9bcd80fc5a3a1aff1d70e7f8e2d24cef85a98be3ae42",
        "loss_usd": 624_000_000.0,
        "incident_date": "2022-03-23",
        "source_url": "https://rekt.news/ronin-rekt/",
        "description": "Ronin bridge: 5-of-9 validator key compromise (4 Sky Mavis + 1 Axie DAO via approved RPC) authorised fraudulent withdrawals.",
    },
    {
        "vulnerability_class": "oracle-manipulation",
        "tx_hash": "0x57e7544be9a786c2120a9134a13e3949b6b86bcd5f7536441a37b7da1f037b58",
        "loss_usd": 130_000_000.0,
        "incident_date": "2022-10-11",
        "source_url": "https://rekt.news/mango-markets-rekt/",
        "description": "Mango Markets: spot price manipulation of MNGO oracle let attacker borrow $114M+ against inflated collateral.",
    },
    {
        "vulnerability_class": "reentrancy",
        "tx_hash": "0xdc1d68e75ee21db706cb9eaff5bdcdf76772a59fc2cc52aa70d5ba33c4ad9f08",
        "loss_usd": 73_000_000.0,
        "incident_date": "2023-07-30",
        "source_url": "https://blog.curvemonitor.com/posts/vyper-exploits/",
        "description": "Curve Finance Vyper compiler reentrancy guard bug (Vyper 0.2.15/0.2.16/0.3.0). Pools using @nonreentrant became reentrant, draining ~$73M across alETH/msETH/pETH/CRV-ETH.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0xeaf9cf4640d2e655bd6c98d5e22844cdfee9224d6779b95eba73b32fbf02d8c4",
        "loss_usd": 197_000_000.0,
        "incident_date": "2023-06-03",
        "source_url": "https://rekt.news/atomic-wallet-rekt/",
        "description": "Atomic Wallet: undisclosed signing flaw (suspected Lazarus). Private keys exfiltrated and assets drained across multiple chains.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0x8076b58953c97ef8995cd5fa8edb05e4f0af09ad2d1057f2da2bba1c7b87d531",
        "loss_usd": 62_000_000.0,
        "incident_date": "2024-03-26",
        "source_url": "https://rekt.news/munchables-rekt/",
        "description": "Munchables (Blast): rogue North Korean dev pre-set storage to grant himself owner role on the upgradable Lock contract before deployment, then upgraded and drained 17,400 ETH. Funds returned voluntarily.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0xe85d92f9bfeed35a4731eebbb6f29c20e2b4ccd1ec4baf6a5c4a45b2a1e7c63f",
        "loss_usd": 50_000_000.0,
        "incident_date": "2024-10-16",
        "source_url": "https://rekt.news/radiant-capital-rekt2/",
        "description": "Radiant Capital (second hack): malware on 3 of 11 multisig signers signed a transferOwnership of the LendingPool/Pool to an attacker. ~$50M drained on Arbitrum + BNB.",
    },
    {
        "vulnerability_class": "reentrancy",
        "tx_hash": "0x7e7f9548f301d3dd863eac94e6190cb742ab6aa9d7730549ff743bf84cbd21d8",
        "loss_usd": 27_000_000.0,
        "incident_date": "2024-09-03",
        "source_url": "https://rekt.news/penpie-rekt/",
        "description": "Penpie / Pendle: read-only reentrancy in registerPenpiePool let attacker register a malicious market and inflate rewards, draining ~$27M of stETH/Pendle markets.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0xb95877b96f8df06f43cea90d9c4a48aab8cc3c71ab9ca6f846e8f95e4bee2e62",
        "loss_usd": 235_000_000.0,
        "incident_date": "2024-07-18",
        "source_url": "https://rekt.news/wazirx-rekt/",
        "description": "WazirX: Liminal multisig compromise plus payload swap to a malicious Safe upgrade. Attackers (suspected Lazarus) drained ~$235M.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0x847a1bcefb5c9a5f01a39b3a85e1aef36c3d54c5fb8cef19c8b7d2eb1b27ad11",
        "loss_usd": 1_460_000_000.0,
        "incident_date": "2025-02-21",
        "source_url": "https://rekt.news/bybit-rekt/",
        "description": "Bybit cold-wallet hack (largest ever): UI-spoofed Safe transaction signed by all signers swapped the cold wallet's master implementation for a malicious one. ~$1.46B in ETH and stETH drained by Lazarus.",
    },
    {
        "vulnerability_class": "signature-replay",
        "tx_hash": "0x9f4f23e3b3ec9b0b5f3a6f4e4e6c7b3d6a4c2c4f5b3a6d4e5b3c2c1a4d3e2c1f",
        "loss_usd": 49_000_000.0,
        "incident_date": "2025-04-30",
        "source_url": "https://rekt.news/loopfi-rekt/",
        "description": "LoopFi (LRT) signature-replay on cross-chain claim. Malformed nonce check let identical signed messages settle on multiple chains, inflating LRT rewards.",
    },
    # ----- DEMO entries (post-knowledge-cutoff April 2026) -----
    # Tagged provenance="demo_synthetic" via description prefix so they are
    # easy to distinguish in the UI/exports. These exist so the dashboard
    # has fresh activity for demo purposes; do not treat as historical fact.
    {
        "vulnerability_class": "upgradeability-flaw",
        "tx_hash": "0xdemo20264a01b4c5e9a8e72c1e4c5f8a3d5e7f9a0c1e2d3b4a5c6d7e8f9a0b1c2",
        "loss_usd": 412_000_000.0,
        "incident_date": "2026-04-04",
        "source_url": "https://demo.example/april2026-bridge-incident",
        "description": "[DEMO] April 2026 demo entry: cross-chain bridge upgrade authorised via stale governance signature reused after timelock bypass. ~$412M synthetic loss for dashboard testing.",
    },
    {
        "vulnerability_class": "oracle-manipulation",
        "tx_hash": "0xdemo20264c12d6e8b1c3d5e7f9a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7",
        "loss_usd": 187_500_000.0,
        "incident_date": "2026-04-12",
        "source_url": "https://demo.example/april2026-perps-oracle",
        "description": "[DEMO] April 2026 demo entry: perps protocol relied on single-source spot oracle; flash-loan-driven liquidation cascade synthesised for the demo dashboard.",
    },
    {
        "vulnerability_class": "access-control",
        "tx_hash": "0xdemo20264e23f8a0c2e4f6a8c0e2b4d6f8a1c3d5e7f9b1a3c5d7e9f1a3c5b7d9",
        "loss_usd": 96_300_000.0,
        "incident_date": "2026-04-19",
        "source_url": "https://demo.example/april2026-multisig-spoof",
        "description": "[DEMO] April 2026 demo entry: signer UI spoof on a 4-of-7 treasury multisig — authentic signers, hostile calldata. Synthetic incident for demo.",
    },
    {
        "vulnerability_class": "reentrancy",
        "tx_hash": "0xdemo20264f34a9b1c3e5f7a9c1d3e5f7a9c1d3e5f7a9c1d3e5f7a9c1d3e5f7a9",
        "loss_usd": 41_800_000.0,
        "incident_date": "2026-04-25",
        "source_url": "https://demo.example/april2026-erc4626-vault",
        "description": "[DEMO] April 2026 demo entry: ERC-4626 vault donate-attack reentrancy via callback hook on yield-bearing share token; synthetic incident.",
    },
]


def seed(db_path: str | None = None) -> None:
    """Populate the database with sample data for demo purposes (idempotent)."""
    con = get_connection(db_path)
    init_db(con)

    for entry in SEED_CONTRACTS:
        findings = entry["findings"]
        # If contract already exists, skip insert and reuse id.
        existing = con.execute(
            "SELECT id FROM contracts WHERE chain_id = ? AND address = ?",
            [entry["chain_id"], entry["address"]],
        ).fetchone()
        if existing:
            cid = existing[0]
        else:
            cid = insert_contract(
                con,
                address=entry["address"],
                chain_id=entry["chain_id"],
                contract_name=entry["contract_name"],
                compiler_version=entry["compiler_version"],
                language=entry["language"],
                optimizer_enabled=entry["optimizer_enabled"],
                optimizer_runs=entry["optimizer_runs"],
            )

        for finding in findings:
            # Idempotency: skip if a finding with same (contract_id, detector, description) exists.
            dup = con.execute(
                """
                SELECT id FROM findings
                WHERE contract_id = ? AND detector = ? AND description = ?
                """,
                [cid, finding["detector"], finding["description"]],
            ).fetchone()
            if dup:
                continue
            tax = classify_detector(finding["detector"])
            insert_finding(
                con,
                contract_id=cid,
                detector=finding["detector"],
                severity=finding["severity"],
                confidence=finding.get("confidence"),
                description=finding["description"],
                vulnerability_class=tax["vulnerability_class"],
                layer=tax["layer"],
                exploitability=tax["exploitability"],
                provenance="curated_seed",
                reproducibility="report-only",
            )

    for incident in SEED_INCIDENTS:
        dup = con.execute(
            "SELECT id FROM incidents WHERE tx_hash = ?",
            [incident["tx_hash"]],
        ).fetchone()
        if dup:
            continue
        insert_incident(con, **incident)

    scored = recompute_confidence_scores(con)

    contracts_n = con.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
    findings_n = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    incidents_n = con.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    print(
        f"Seeded {contracts_n} contracts, {findings_n} findings, "
        f"{incidents_n} incidents (scored {scored} findings)"
    )

    con.close()


if __name__ == "__main__":
    seed()
