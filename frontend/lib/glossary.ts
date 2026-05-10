// Plain-language glossary surfaced in tooltips across the UI.
// Keep entries short — one or two sentences. Use phrasing a smart engineer
// who hasn't lived in audit world would understand on first read.

export const VULN_CLASS_LABELS: Record<string, string> = {
  reentrancy: "Reentrancy",
  "access-control": "Access control",
  access_control: "Access control",
  authz_bypass: "Authorization bypass",
  accounting_error: "Accounting error",
  "accounting-error": "Accounting error",
  oracle_manipulation: "Oracle manipulation",
  "oracle-dependence": "Oracle dependence",
  precision_rounding: "Precision / rounding",
  storage_collision: "Storage collision",
  "storage-collision": "Storage collision",
  initialization_bug: "Initialization bug",
  "initialization-bug": "Initialization bug",
  upgradeability_flaw: "Upgradeability flaw",
  "upgradeability-flaw": "Upgradeability flaw",
  signature_replay: "Signature replay",
  liquidation_bug: "Liquidation bug",
  flashloan_abuse: "Flashloan abuse",
  governance_capture: "Governance capture",
  zk_circuit_bug: "ZK circuit bug",
  mev_composability: "MEV composability",
  "tx-origin": "tx.origin auth",
  "timestamp-dependence": "Timestamp dependence",
  "unchecked-call": "Unchecked external call",
  "self-destruct": "Selfdestruct hazard",
  "integer-overflow": "Integer overflow",
  "missing-zero-check": "Missing zero-address check",
  "centralization-risk": "Centralization risk",
  other: "Other",
  unclassified: "Unclassified",
};

export const VULN_CLASS_DESCRIPTIONS: Record<string, string> = {
  reentrancy:
    "External call returns control to the attacker mid-transaction before state updates settle. Drains follow when balances aren't decremented before the call. Classic example: TheDAO, Cream, Lendf.me.",
  "access-control":
    "Privileged function — mint, withdraw, upgrade, set owner — is callable by anyone because the modifier was missing or wrong. The single biggest dollar-loss class in our dataset.",
  access_control:
    "Privileged function — mint, withdraw, upgrade, set owner — is callable by anyone because the modifier was missing or wrong. The single biggest dollar-loss class in our dataset.",
  authz_bypass:
    "Authorization check exists but the attacker reaches the protected state through a different path: a delegatecall, a fallback, an unchecked routing function. Beanstalk's flashloan-bought governance vote is the textbook case.",
  accounting_error:
    "The protocol's bookkeeping is internally inconsistent: a balance isn't decremented, a share supply gets cached wrong, a refund happens twice. No single attacker action is exotic — the math just doesn't add up. Euler's donateToReserves shape sits here.",
  "accounting-error":
    "The protocol's bookkeeping is internally inconsistent: a balance isn't decremented, a share supply gets cached wrong, a refund happens twice. No single attacker action is exotic — the math just doesn't add up.",
  oracle_manipulation:
    "Price oracle is read from a source the attacker can move — a thin AMM pool, a single feed, a stale TWAP. Combined with a flashloan, the attacker pumps the oracle, takes a loan against the wrong price, repays. Mango, Cream-2, Bunny.",
  "oracle-dependence":
    "Logic depends on an external price/rate without enough validation. Manipulable feeds, missing staleness checks, unchecked deviations. The most common precondition for flashloan attacks.",
  precision_rounding:
    "Rounding direction or decimal handling lets the attacker carve out free value: first-depositor share inflation, donation rounding, decimal mismatch on rebase tokens. Compound-fork share inflation is the canonical example.",
  storage_collision:
    "Two state variables sit in the same storage slot — usually because of a misaligned proxy upgrade or struct packing. Writing one silently overwrites the other.",
  "storage-collision":
    "Two state variables sit in the same storage slot — usually because of a misaligned proxy upgrade or struct packing. Writing one silently overwrites the other.",
  initialization_bug:
    "The implementation contract was deployed but never properly initialised, OR the initializer is callable by anyone, OR a v2 init was skipped during upgrade. Audius and Parity multisig fall here.",
  "initialization-bug":
    "Initializer of a proxy / upgradeable contract is missing, callable by anyone, or skipped during upgrade. Audius and Parity multisig fall here.",
  upgradeability_flaw:
    "Upgrade machinery is unguarded: missing _disableInitializers, no admin gate on _authorizeUpgrade, an open UUPS proxy. Attacker pushes a malicious implementation and drains.",
  "upgradeability-flaw":
    "Upgrade machinery is unguarded: missing _disableInitializers, no admin gate on _authorizeUpgrade, an open UUPS proxy. Attacker pushes a malicious implementation and drains.",
  signature_replay:
    "ECDSA signature can be replayed across chains, contracts, or transactions because nonce / chainId / domainSeparator is missing. Wormhole and Portal sit close to this category.",
  liquidation_bug:
    "Liquidation engine has a bug — wrong incentive math, MEV-able trigger, missing solvency check post-liquidation. Lets a liquidator take more than they should, or stops liquidations from happening at all.",
  flashloan_abuse:
    "Flashloan is the funding vehicle but the root cause is somewhere else (oracle, accounting, governance). We tag it here only when no deeper category fits — usually means the postmortem is shallow.",
  governance_capture:
    "Attacker accumulates voting power — by flashloan, by buying tokens, by exploiting delegation — and pushes a malicious proposal that drains the treasury or grants admin rights.",
  zk_circuit_bug:
    "Soundness break in a SNARK/STARK circuit: bad trusted setup, missing constraint, broken pairing check. Any proof verifies, including for transitions that never happened. Veil Cash is our anchor case.",
  mev_composability:
    "Bug surfaces only at the composition layer — MEV bot, solver, settlement contract — interacting with otherwise-correct primitives. Hard to attribute to a single contract.",
  "tx-origin":
    "Authorization check uses tx.origin instead of msg.sender. A user calling a malicious contract that calls the protocol passes the check; classic phishing-amplifier.",
  "timestamp-dependence":
    "Critical logic depends on block.timestamp which miners / validators can nudge by a few seconds. Matters for short-deadline auctions, randomness sources, vesting cliffs.",
  "unchecked-call":
    "Low-level call (.call / .send / .transfer) doesn't check the return value, so failures look like successes. Funds get marked as paid when they aren't, or state advances on a no-op.",
  "self-destruct":
    "Contract can selfdestruct (now SENDALL) and reset its bytecode, breaking integrators who assumed code immutability. Parity's second incident is the canonical scar.",
  "integer-overflow":
    "Arithmetic wraps because Solidity <0.8 had no built-in checks. Now mostly historical, but unchecked{} blocks bring it back. BeautyChain (BEC) is the bcalled-out billion-dollar overflow.",
  "missing-zero-check":
    "Setter accepts address(0) without rejecting it, freezing the role / sending tokens to a black hole. Low severity but shows up everywhere.",
  "centralization-risk":
    "A single key or multisig can pause, mint, freeze, or upgrade. Not a bug per se, but every integrator inherits that trust assumption. We surface it because incidents like Ronin start as 'just centralization' until the keys leak.",
  other:
    "Doesn't cleanly fit any class — usually because the postmortem is missing or the bug spans multiple categories. Manual review needed.",
  unclassified:
    "We haven't tagged this one yet. Either Slither didn't recognise the detector or the entry came in without taxonomy fields.",
};

export const LAYER_LABELS: Record<string, string> = {
  solidity_source: "Solidity source",
  protocol_logic: "Protocol logic",
  integration: "Integration",
  proxy_storage: "Proxy / storage",
  tokenomics: "Tokenomics",
  compiler_config: "Compiler / config",
  unclassified: "Unclassified",
};

export const LAYER_DESCRIPTIONS: Record<string, string> = {
  solidity_source:
    "Bug lives in the Solidity source of one specific contract — a missing modifier, a wrong require, an off-by-one. Fixable by editing that file.",
  protocol_logic:
    "Bug is in how the protocol's pieces compose — accounting flow, AMM curve, lending engine. The individual contracts may all be 'correct' in isolation; their interaction isn't.",
  integration:
    "Bug surfaces when this contract talks to another protocol — a bridge, a callback (Uniswap V2/3, Aave flashloan), a cross-chain message. Root cause is in the seam, not in either side alone.",
  proxy_storage:
    "Bug is in the proxy / storage layout — slot collision, missed initializer, wrong implementation pointer, unsafe storage gap. Surfaces during upgrades.",
  tokenomics:
    "Bug is in the incentive design itself — emission curve, fee distribution, voting weight, rebase mechanics. Code is doing what it was told; the design was the bug.",
  compiler_config:
    "Bug comes from compiler / optimizer behaviour — Solidity miscompilations, Yul optimizer regressions, wrong evmVersion. Rare but extremely high-impact when it happens.",
  unclassified:
    "Hasn't been tagged with a layer yet.",
};

export const ENTITY_DESCRIPTIONS = {
  contracts:
    "Verified Solidity contracts pulled from Sourcify. Each one carries source code, ABI, compiler settings, and storage layout. The substrate the rest of the atlas annotates.",
  findings:
    "Individual security observations attached to a contract — produced by Slither static analysis plus our own heuristic detectors. Each finding has severity, vulnerability class, and architecture layer.",
  incidents:
    "Historical hacks. Curated post-mortems mapped onto our taxonomy: name, date, chain, loss in USD, vulnerability class. The 'ground truth' anchors that pin abstract classes to real exploits.",
  synthetic:
    "Generated (vulnerable, patched) Solidity pairs. Anchored on real seed contracts and produced by deterministic mutation rules — not LLM output. Used as training and benchmark material.",
  embeddings:
    "Vector index over contracts + synthetic + incidents. TF-IDF → SVD → 128-dim vectors → UMAP for the explorer scatter. Powers similarity search, clustering, and novelty scoring.",
  loss:
    "Sum of reported USD losses across all tracked incidents. Source: DefiLlama hacks dataset, filtered to Solidity-only and curated post-classification.",
};
