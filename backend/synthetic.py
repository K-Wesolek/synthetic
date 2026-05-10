"""Synthetic dataset generator.

Produces (vulnerable, patched) Solidity source pairs anchored on the curated
seed cases. The generator is rule-based and deterministic so the synthetic
slice of the database is reproducible and testable without an LLM in the loop.

Each generated case includes:
  * vulnerability_class / layer / exploitability (PROJECT.md taxonomy)
  * a vulnerable solidity snippet
  * a patched solidity snippet (the inverse mutation)
  * an exploit precondition string (what the attacker needs)
  * a benchmark task description (what a model is asked to produce)
  * provenance + generator metadata

Usage:
    python3 -m backend.synthetic              # default 24 cases
    python3 -m backend.synthetic --count 60   # generate 60 cases
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from backend.db_enhanced import (
    DB_PATH,
    get_connection,
    init_db,
    insert_synthetic_case,
    list_synthetic_cases,
)

GENERATOR_NAME = "rule-based-mutator"
GENERATOR_VERSION = "0.1.0"


@dataclass(frozen=True)
class Mutation:
    name: str
    vulnerability_class: str
    layer: str
    exploitability: str
    severity: str
    title: str
    description: str
    exploit_precondition: str
    vulnerable: str
    patched: str
    benchmark_task: str = "Identify the bug, classify it, and produce a patch."


# ---------------------------------------------------------------------------
# Mutation templates: each template defines a paired (vulnerable, patched) snippet
# ---------------------------------------------------------------------------

REENTRANCY_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    mapping(address => uint256) public balance;

    function deposit() external payable {{
        balance[msg.sender] += msg.value;
    }}

    function withdraw(uint256 amount) external {{
        require(balance[msg.sender] >= amount, "insufficient");
        // VULN: external call before state update
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok, "send failed");
        balance[msg.sender] -= amount;
    }}
}}
"""

REENTRANCY_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    mapping(address => uint256) public balance;
    bool private locked;

    modifier nonReentrant() {{
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }}

    function deposit() external payable {{
        balance[msg.sender] += msg.value;
    }}

    function withdraw(uint256 amount) external nonReentrant {{
        require(balance[msg.sender] >= amount, "insufficient");
        // PATCH: checks-effects-interactions; debit before external call
        balance[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{{value: amount}}("");
        require(ok, "send failed");
    }}
}}
"""

ACCESS_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;

    constructor() {{ owner = msg.sender; }}

    // VULN: critical setter is unprotected
    function setOwner(address newOwner) external {{
        owner = newOwner;
    }}

    function withdraw() external {{
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
"""

ACCESS_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;

    constructor() {{ owner = msg.sender; }}

    modifier onlyOwner() {{
        require(msg.sender == owner, "not owner");
        _;
    }}

    // PATCH: setOwner is owner-gated and rejects zero address
    function setOwner(address newOwner) external onlyOwner {{
        require(newOwner != address(0), "zero owner");
        owner = newOwner;
    }}

    function withdraw() external onlyOwner {{
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
"""

INIT_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;
    bool public initialized;

    // VULN: anyone can call initialize again because the guard is missing
    function initialize(address _owner) external {{
        owner = _owner;
        initialized = true;
    }}
}}
"""

INIT_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;
    bool public initialized;

    function initialize(address _owner) external {{
        require(!initialized, "already initialized");
        require(_owner != address(0), "zero owner");
        owner = _owner;
        initialized = true;
    }}
}}
"""

OVERFLOW_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract {name} {{
    mapping(address => uint256) public balance;

    // VULN: pre-0.8 unchecked arithmetic — multiplication can overflow
    function batchTransfer(address[] _to, uint256 _value) public returns (bool) {{
        uint256 amount = uint256(_to.length) * _value;
        require(_value > 0 && balance[msg.sender] >= amount);
        balance[msg.sender] -= amount;
        for (uint i = 0; i < _to.length; i++) {{
            balance[_to[i]] += _value;
        }}
        return true;
    }}
}}
"""

OVERFLOW_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    mapping(address => uint256) public balance;

    function batchTransfer(address[] calldata _to, uint256 _value) external returns (bool) {{
        // PATCH: 0.8.x has built-in overflow checks; explicit length cap as belt-and-suspenders
        require(_to.length < 1024, "batch too large");
        uint256 amount = _to.length * _value;
        require(_value > 0 && balance[msg.sender] >= amount, "insufficient");
        balance[msg.sender] -= amount;
        for (uint256 i = 0; i < _to.length; i++) {{
            balance[_to[i]] += _value;
        }}
        return true;
    }}
}}
"""

UNCHECKED_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {{ function transfer(address, uint256) external returns (bool); }}

contract {name} {{
    IToken public token;

    constructor(IToken t) {{ token = t; }}

    // VULN: return value of transfer is ignored
    function payout(address to, uint256 amount) external {{
        token.transfer(to, amount);
    }}
}}
"""

UNCHECKED_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {{ function transfer(address, uint256) external returns (bool); }}

contract {name} {{
    IToken public token;

    constructor(IToken t) {{ token = t; }}

    function payout(address to, uint256 amount) external {{
        // PATCH: check the return value
        bool ok = token.transfer(to, amount);
        require(ok, "transfer failed");
    }}
}}
"""

DELEGATECALL_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public implementation;

    // VULN: anyone can swap the delegatecall target
    function setImplementation(address impl) external {{
        implementation = impl;
    }}

    fallback() external payable {{
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "delegatecall failed");
    }}
}}
"""

DELEGATECALL_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public implementation;
    address public admin;

    constructor() {{ admin = msg.sender; }}

    function setImplementation(address impl) external {{
        require(msg.sender == admin, "not admin");
        require(impl.code.length > 0, "not a contract");
        implementation = impl;
    }}

    fallback() external payable {{
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "delegatecall failed");
    }}
}}
"""

ORACLE_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPair {{ function getReserves() external view returns (uint112, uint112, uint32); }}

contract {name} {{
    IPair public pair;

    constructor(IPair p) {{ pair = p; }}

    // VULN: spot price from a single AMM is trivially manipulated by flash loans
    function priceOf() external view returns (uint256) {{
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }}
}}
"""

ORACLE_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IChainlink {{ function latestAnswer() external view returns (int256); }}

contract {name} {{
    IChainlink public oracle;

    constructor(IChainlink o) {{ oracle = o; }}

    function priceOf() external view returns (uint256) {{
        // PATCH: read from a tamper-resistant oracle (Chainlink) instead of a spot AMM
        int256 answer = oracle.latestAnswer();
        require(answer > 0, "stale price");
        return uint256(answer);
    }}
}}
"""

TX_ORIGIN_VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;
    constructor() {{ owner = msg.sender; }}

    // VULN: tx.origin allows phishing via malicious intermediate contracts
    modifier onlyOwner() {{ require(tx.origin == owner, "not owner"); _; }}

    function withdraw() external onlyOwner {{
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
"""

TX_ORIGIN_PATCH = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {name} {{
    address public owner;
    constructor() {{ owner = msg.sender; }}

    modifier onlyOwner() {{ require(msg.sender == owner, "not owner"); _; }}

    function withdraw() external onlyOwner {{
        payable(msg.sender).transfer(address(this).balance);
    }}
}}
"""

MUTATIONS: list[Mutation] = [
    Mutation(
        name="reentrancy_classic",
        vulnerability_class="reentrancy",
        layer="protocol-logic",
        exploitability="direct-drain",
        severity="High",
        title="Classic withdraw() reentrancy",
        description="External call to msg.sender precedes the balance debit, allowing recursive withdraw drains.",
        exploit_precondition="Attacker contract with a fallback() that re-enters withdraw() before balance is updated.",
        vulnerable=REENTRANCY_VULN,
        patched=REENTRANCY_PATCH,
    ),
    Mutation(
        name="missing_owner_check",
        vulnerability_class="access-control",
        layer="protocol-logic",
        exploitability="privilege-escalation",
        severity="High",
        title="Unprotected owner setter",
        description="setOwner() lacks an owner check, letting any caller seize ownership and drain funds.",
        exploit_precondition="Direct call to setOwner(attacker) followed by withdraw().",
        vulnerable=ACCESS_VULN,
        patched=ACCESS_PATCH,
    ),
    Mutation(
        name="initialize_no_guard",
        vulnerability_class="initialization-bug",
        layer="protocol-logic",
        exploitability="privilege-escalation",
        severity="High",
        title="Re-callable initialize()",
        description="initialize() omits the !initialized guard so anyone can re-initialize ownership.",
        exploit_precondition="Call initialize(attacker) on a deployed-but-public proxy/logic contract.",
        vulnerable=INIT_VULN,
        patched=INIT_PATCH,
    ),
    Mutation(
        name="batch_overflow",
        vulnerability_class="integer-overflow",
        layer="solidity-source",
        exploitability="dilution",
        severity="High",
        title="Pre-0.8 batchTransfer overflow",
        description="length * value overflows uint256, leaving balance[sender] unchanged while crediting recipients.",
        exploit_precondition="Provide a long array with a huge _value such that length*_value wraps to a small number.",
        vulnerable=OVERFLOW_VULN,
        patched=OVERFLOW_PATCH,
    ),
    Mutation(
        name="unchecked_transfer",
        vulnerability_class="unchecked-call",
        layer="integration",
        exploitability="griefing-dos",
        severity="Medium",
        title="Ignored ERC20 transfer return",
        description="payout() ignores transfer's return value, silently dropping failed transfers.",
        exploit_precondition="Use a token that returns false on failure (e.g. some ERC20 implementations).",
        vulnerable=UNCHECKED_VULN,
        patched=UNCHECKED_PATCH,
    ),
    Mutation(
        name="unprotected_delegatecall",
        vulnerability_class="upgradeability-flaw",
        layer="proxy-storage",
        exploitability="direct-drain",
        severity="High",
        title="Public setImplementation",
        description="Anyone can rewire the proxy's implementation pointer, hijacking storage and balances.",
        exploit_precondition="Deploy a malicious implementation, call setImplementation(attacker).",
        vulnerable=DELEGATECALL_VULN,
        patched=DELEGATECALL_PATCH,
    ),
    Mutation(
        name="amm_spot_oracle",
        vulnerability_class="oracle-manipulation",
        layer="integration",
        exploitability="direct-drain",
        severity="High",
        title="AMM spot price as oracle",
        description="priceOf() reads instantaneous Uniswap-style reserves; flash loans can move price arbitrarily.",
        exploit_precondition="Flash-loan into the pool, query price during the loan, repay loan.",
        vulnerable=ORACLE_VULN,
        patched=ORACLE_PATCH,
    ),
    Mutation(
        name="tx_origin_auth",
        vulnerability_class="tx-origin",
        layer="solidity-source",
        exploitability="privilege-escalation",
        severity="Medium",
        title="tx.origin used for authorization",
        description="Owner check uses tx.origin instead of msg.sender, enabling phishing via intermediate contracts.",
        exploit_precondition="Owner is convinced to call attacker contract that proxies into withdraw().",
        vulnerable=TX_ORIGIN_VULN,
        patched=TX_ORIGIN_PATCH,
    ),
]


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def _case_uid(mutation: Mutation, anchor_name: str | None, idx: int) -> str:
    """Stable content-derived id so reruns are idempotent."""
    raw = f"{GENERATOR_NAME}|{GENERATOR_VERSION}|{mutation.name}|{anchor_name}|{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def generate(con, count: int = 24) -> list[dict]:
    """Generate ``count`` synthetic cases by cycling through templates and seed contracts.

    Each anchor contract gets paired with mutations that match a finding present
    on it where possible; otherwise mutations are spread round-robin so the
    output covers every taxonomy class.
    """
    init_db(con)

    # Pull anchor candidates: contract + class for every existing finding.
    anchor_rows = con.execute(
        """
        SELECT f.id AS finding_id, f.contract_id, f.vulnerability_class,
               c.contract_name
        FROM findings f
        JOIN contracts c ON c.id = f.contract_id
        """
    ).fetchall()
    anchors_by_class: dict[str, list[tuple]] = {}
    for finding_id, contract_id, vclass, name in anchor_rows:
        anchors_by_class.setdefault(vclass or "other", []).append(
            (finding_id, contract_id, name)
        )

    inserted: list[dict] = []
    idx = 0
    for i in range(count):
        mutation = MUTATIONS[i % len(MUTATIONS)]
        anchors = anchors_by_class.get(mutation.vulnerability_class) or [(None, None, None)]
        finding_id, contract_id, anchor_name = anchors[i % len(anchors)]

        contract_name = f"Synthetic_{mutation.name}_{i:03d}"
        vulnerable = mutation.vulnerable.format(name=contract_name)
        patched = mutation.patched.format(name=contract_name)

        case_uid = _case_uid(mutation, anchor_name, i)
        row_id = insert_synthetic_case(
            con,
            case_uid=case_uid,
            anchor_contract_id=contract_id,
            anchor_finding_id=finding_id,
            vulnerability_class=mutation.vulnerability_class,
            layer=mutation.layer,
            exploitability=mutation.exploitability,
            severity=mutation.severity,
            title=mutation.title,
            description=mutation.description,
            vulnerable_source=vulnerable,
            patched_source=patched,
            exploit_precondition=mutation.exploit_precondition,
            benchmark_task=mutation.benchmark_task,
            generator=GENERATOR_NAME,
            generator_version=GENERATOR_VERSION,
        )
        inserted.append({"id": row_id, "case_uid": case_uid, "mutation": mutation.name})
        idx += 1

    return inserted


# ---------------------------------------------------------------------------
# Parquet export of the synthetic slice
# ---------------------------------------------------------------------------

def export_synthetic_parquet(con, out_dir: str = "slices") -> str:
    """Write the synthetic_cases table to a versioned Parquet file. Returns path."""
    from backend.query import DATASET_VERSION, dataset_manifest

    rows = con.execute(
        """
        SELECT s.case_uid, s.vulnerability_class, s.layer, s.exploitability,
               s.severity, s.title, s.description, s.exploit_precondition,
               s.benchmark_task, s.provenance, s.generator, s.generator_version,
               s.created_at, s.vulnerable_source, s.patched_source,
               c.address AS anchor_address, c.contract_name AS anchor_name,
               c.chain_id AS anchor_chain_id
        FROM synthetic_cases s
        LEFT JOIN contracts c ON s.anchor_contract_id = c.id
        ORDER BY s.id
        """
    ).fetchall()
    cols = [d[0] for d in con.description]
    df = pd.DataFrame(rows, columns=cols)

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = str(Path(out_dir) / f"synthetic_dataset_{DATASET_VERSION}.parquet")

    table = pa.Table.from_pandas(df)
    manifest = dataset_manifest(con, extra={"slice": "synthetic_cases", "rows": len(df)})
    schema_with_meta = table.schema.with_metadata(
        {b"atlas_manifest": json.dumps(manifest).encode("utf-8")}
    )
    table = table.replace_schema_metadata(schema_with_meta.metadata)
    pq.write_table(table, path)

    sidecar = Path(path).with_suffix(".manifest.json")
    sidecar.write_text(json.dumps(manifest, indent=2))
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic vulnerability cases")
    parser.add_argument("--count", type=int, default=24,
                        help="Number of synthetic cases to generate (default 24)")
    parser.add_argument("--db", default=DB_PATH, help="Path to atlas.duckdb")
    parser.add_argument("--export", action="store_true",
                        help="Also write slices/synthetic_dataset.parquet")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
    con = get_connection(args.db)
    inserted = generate(con, count=args.count)
    print(f"Synthetic cases now in DB: {len(list_synthetic_cases(con, limit=10_000))}")
    print(f"This run added or reused {len(inserted)} cases")

    if args.export:
        path = export_synthetic_parquet(con)
        print(f"Wrote {path}")

    con.close()


if __name__ == "__main__":
    main()
