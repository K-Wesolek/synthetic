"""Seed the DuckDB database with known vulnerable contracts and findings.

Run: python -m backend.seed
"""

from pathlib import Path

from backend.db import get_connection, init_db, insert_contract, insert_finding, insert_incident

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
]


def seed(db_path: str | None = None) -> None:
    """Populate the database with sample data for demo purposes."""
    con = get_connection(db_path)
    init_db(con)

    for contract_data in SEED_CONTRACTS:
        findings = contract_data.pop("findings")
        cid = insert_contract(con, **contract_data)
        for finding in findings:
            insert_finding(con, contract_id=cid, **finding)
        contract_data["findings"] = findings  # restore for re-runnability

    for incident_data in SEED_INCIDENTS:
        insert_incident(con, **incident_data)

    row = con.execute("SELECT COUNT(*) FROM contracts").fetchone()
    print(f"Seeded {row[0]} contracts")
    row = con.execute("SELECT COUNT(*) FROM findings").fetchone()
    print(f"Seeded {row[0]} findings")
    row = con.execute("SELECT COUNT(*) FROM incidents").fetchone()
    print(f"Seeded {row[0]} incidents")

    con.close()


if __name__ == "__main__":
    seed()
