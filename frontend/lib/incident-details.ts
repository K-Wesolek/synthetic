// Curated incident annotations layered on top of /api/incidents.
// Frontend-only — extends the API record with technical + plain-language
// breakdowns, transaction hashes, and references. The user wants per-incident
// drill-downs without backend changes.

import type { Incident } from "./api";

export interface TimelineEntry {
  time: string;        // ISO or human; rendered as-is
  event: string;
}

export interface IncidentReference {
  title: string;
  url: string;
}

export interface ContractRef {
  label: string;
  address: string;
  chain?: string;
  role?: string;       // e.g. "OFT adapter", "EndpointV2"
}

export interface IncidentDetail {
  // Display
  headline: string;
  summary: string;             // one-sentence elevator pitch
  plain_language: string[];    // paragraphs, written for a smart non-engineer
  technical: string[];         // bullet-style technical mechanism
  // Forensics
  tokens_lost?: string;        // "116,500 rsETH (~18% of supply)"
  loss_usd_label?: string;     // overrides API loss formatting if needed
  attack_vector?: string;      // short label, e.g. "1-of-1 DVN trust assumption"
  layer?: string;              // e.g. "cross-chain bridge", "off-chain infra"
  attacker_address?: string;
  tx_hashes?: string[];
  contracts_involved?: ContractRef[];
  timeline?: TimelineEntry[];
  consequences?: string[];     // bullets describing aftermath
  references: IncidentReference[];
  // Attribution: detail "owns" an API row when txHash matches OR the synthetic
  // id is appended via INJECTED_INCIDENTS.
}

// ──────────────────────────────────────────────────────────────────────────
// Detail lookup keyed by tx_hash (when API row has one) or synthetic id
// (for incidents we inject ourselves)
// ──────────────────────────────────────────────────────────────────────────

export const INCIDENT_DETAILS: Record<string, IncidentDetail> = {
  // Kelp DAO — injected, see below
  "kelp-rseth-2026-04-18": {
    headline: "Kelp DAO rsETH bridge — $292M phantom mint",
    summary:
      "Attackers tricked Kelp's single-verifier LayerZero bridge into releasing 116,500 rsETH (~18% of supply) without any backing deposit, then dumped through Aave and Fluid as collateral.",
    plain_language: [
      "rsETH is a token that represents a deposit inside Kelp DAO's restaking protocol — every rsETH on Ethereum is supposed to be backed by ETH locked elsewhere. To move rsETH between chains, Kelp used LayerZero, a cross-chain messaging system. Critically, only one independent party (a 'DVN' — decentralised verifier network) had to vouch for each cross-chain message.",
      "The attackers, linked to North Korea's Lazarus Group, did not break any smart contract. Instead they took over the data sources that the lone verifier was reading from, and DDoS'd the others offline. With the verifier looking at fabricated data, they sent it a forged proof saying 'this much rsETH was just burned on the source chain — please mint it on Ethereum.' Nothing had actually been burned. The bridge minted 116,500 fresh rsETH out of thin air.",
      "They immediately deposited the phantom rsETH as collateral on Aave V3 / V4 and Fluid and borrowed roughly $200M+ of legitimate stablecoins and ETH against it. By the time Kelp paused the bridge 46 minutes later, the borrowed funds were gone and lending markets were stuck holding the rsETH bag. Aave alone wrote off ~$177M in bad debt and triggered a $13B+ exodus from DeFi over the next two days.",
    ],
    technical: [
      "Bridge: LayerZero v2 OFT adapter at 0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3 talking to EndpointV2 0x1a44076050125825900e736c501f859c50fE728c.",
      "DVN configuration: requiredDVNs=[LayerZero Labs], requiredDVNCount=1, no optional verifiers — a single signature was sufficient authorization to release tokens.",
      "Attack path: compromise two upstream RPC nodes feeding the DVN + DDoS the rest → DVN signs a fraudulent attestation for a non-existent burn on the source chain → Ethereum-side adapter calls _credit() and mints 116,500 rsETH to the attacker.",
      "Liquidation path: rsETH → Aave V3/V4 + Fluid as collateral → borrow USDC/WETH → bridge out via Tornado-pattern mixer.",
      "Vulnerability class is configuration / trust-assumption, not a Solidity bug — the OFT adapter behaved exactly as configured. ~47% of LayerZero OApps were running the same 1-of-1 DVN setup at time of incident, exposing >$4.5B of TVL to identical risk.",
    ],
    tokens_lost: "116,500 rsETH (~18% of supply)",
    attack_vector: "1-of-1 DVN trust assumption + off-chain infra compromise",
    layer: "cross-chain bridge / off-chain verification",
    attacker_address: "0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b",
    tx_hashes: [
      "0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222",
    ],
    contracts_involved: [
      {
        label: "rsETH OFT Adapter",
        address: "0x85d456B2DfF1fd8245387C0BfB64Dfb700e98Ef3",
        chain: "Ethereum",
        role: "released tokens on forged proof",
      },
      {
        label: "LayerZero EndpointV2",
        address: "0x1a44076050125825900e736c501f859c50fE728c",
        chain: "Ethereum",
        role: "delivered the spoofed message",
      },
      {
        label: "Attacker EOA",
        address: "0x8B1b6c9A6DB1304000412dd21Ae6A70a82d60D3b",
        chain: "Ethereum",
        role: "received minted rsETH",
      },
    ],
    timeline: [
      { time: "2026-04-18 17:35 UTC", event: "Forged DVN attestation accepted; 116,500 rsETH minted to attacker EOA in tx 0x1ae2…4222." },
      { time: "+2 min",  event: "Attacker deposits rsETH on Aave V3 / V4 and Fluid as collateral." },
      { time: "+5–18 min", event: "Borrows USDC / WETH against the phantom rsETH; routes proceeds out through mixers." },
      { time: "+46 min", event: "Kelp emergency-pauses the bridge, blocking two follow-up drains worth ~$200M." },
      { time: "+2 hours", event: "Aave / Fluid suspend the rsETH market; rsETH price decouples from ETH." },
      { time: "Day 2",  event: "$13B+ flows out of DeFi protocols industry-wide as a confidence shock." },
      { time: "Week 1", event: "Kelp migrates rsETH off LayerZero OFT to Chainlink CCIP; LayerZero and Kelp publicly dispute responsibility for the 1-of-1 setup." },
    ],
    consequences: [
      "~$177M in bad debt across Aave V3 / V4 socialised through risk-fund top-ups.",
      "rsETH temporarily lost its peg to ETH; lending markets froze.",
      "Industry-wide review of single-verifier bridges; CoinGecko / Dune analysis flagged ~$4.5B at identical risk.",
      "Kelp migrated to Chainlink CCIP; LayerZero introduced enforced multi-DVN defaults for new OApps.",
    ],
    references: [
      { title: "Halborn — Explained: The Kelp DAO Hack (April 2026)", url: "https://www.halborn.com/blog/post/explained-the-kelp-dao-hack-april-2026" },
      { title: "DeFiPrime — The KelpDAO rsETH Exploit", url: "https://defiprime.com/kelpdao-rseth-exploit" },
      { title: "Chainalysis — Inside the KelpDAO Bridge Exploit", url: "https://www.chainalysis.com/blog/kelpdao-bridge-exploit-april-2026/" },
      { title: "CoinDesk — Kelp DAO claims LayerZero approved the setup", url: "https://www.coindesk.com/web3/2026/05/05/kelp-claims-that-layerzero-approved-the-setup-it-blamed-for-usd292-million-bridge-hack" },
      { title: "Crypto Times — Kelp's vulnerability flagged 15 months earlier", url: "https://www.cryptotimes.io/2026/04/21/kelp-daos-vulnerability-was-flagged-15-months-ago-defi-failed-to-act/" },
    ],
  },

  // ── Historical anchors with curated detail (keyed by tx_hash where the
  // API record has one). These are concise on purpose — Kelp gets the full
  // treatment because the user asked for it.
  "0xc9b30b517c281e437ef21ca6af9b32ff14b4d1a45e7a403e3e0e6e7e6f06c6f2": {
    headline: "The DAO — recursive call drained 3.6M ETH (~$60M)",
    summary:
      "splitDAO sent ETH before updating internal balances, letting the attacker re-enter and withdraw repeatedly. Forced Ethereum's DAO-fork hard split (ETH/ETC).",
    plain_language: [
      "The DAO was a community-governed investment fund built as a smart contract on Ethereum in 2016. Members could leave at any time by calling splitDAO, which would send their share of ETH back to them.",
      "The bug: splitDAO sent the ETH first, then deducted it from the member's balance. A malicious 'fallback' contract could re-call splitDAO during the ETH transfer, draining the same balance again, recursively. The attacker stacked dozens of nested calls and left with 3.6M ETH (~$60M).",
      "The Ethereum community responded with a hard fork that rolled back the theft. Those who refused the rollback kept the original chain — Ethereum Classic.",
    ],
    technical: [
      "Pattern: external call (transfer ETH) before state update (balance debit).",
      "Attacker contract's fallback() re-enters splitDAO before token balance is decremented.",
      "Mitigation: Checks-Effects-Interactions; reentrancy guards (Mutex / nonReentrant); transfer() vs call.value() with bounded gas.",
    ],
    attacker_address: "0xF35e2cC8E6523d683eD44870f5B7cC785051a77D",
    tx_hashes: ["0xc9b30b517c281e437ef21ca6af9b32ff14b4d1a45e7a403e3e0e6e7e6f06c6f2"],
    layer: "protocol-logic",
    attack_vector: "reentrancy via external call before state update",
    references: [
      { title: "Wikipedia — The DAO", url: "https://en.wikipedia.org/wiki/The_DAO_(organization)" },
    ],
  },

  "0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686c0722c9": {
    headline: "Parity Multisig — uninitialized library hijack",
    summary:
      "WalletLibrary's initWallet was unprotected; anyone could call it and become owner. Drained ~$30M before whitehat rescue.",
    plain_language: [
      "Parity's multisig wallets all delegated their core logic to one shared library contract. The library exposed an initWallet function that was meant to run once during deployment, but on the library itself it had never been called — so it stayed callable by anyone.",
      "An attacker called initWallet on the library, set themselves as the owner, then drained the funds delegating through it.",
    ],
    technical: [
      "DELEGATECALL pattern with shared library; initialization function lacked a 'cannot be called twice' guard on the library instance.",
      "Mitigation: initializer modifier (OZ Initializable), constructor-only setup, or self-destructed library after deployment.",
    ],
    attacker_address: "0xb3764761e297d6f121e79c32a65829cd1ddb4d32",
    tx_hashes: ["0x05f71e1b2cb4f03e547739db15d080fd30c989eda04d37ce6264c5686c0722c9"],
    layer: "access-control",
    attack_vector: "uninitialized library / public initializer",
    references: [
      { title: "OpenZeppelin — On the Parity Wallet Multisig Hack", url: "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7" },
    ],
  },

  "0x0570400e38e50c70fa25d3aac496f6e937a6bf7b08e45bcf22e6fa6f3e2afbe6": {
    headline: "Parity wallet freeze — selfdestruct kills shared library",
    summary:
      "An accidental kill() on the WalletLibrary singleton bricked every multisig delegating to it. ~513k ETH (~$150M) frozen, never recovered.",
    plain_language: [
      "Months after the first Parity hack, a user accidentally became the owner of the Parity WalletLibrary (same uninitialized initWallet bug, again), then called kill() on it.",
      "Every multisig wallet that delegated to that library was now pointing at empty bytecode. Funds weren't stolen — they're still in the wallet contracts — but no code can be executed to retrieve them.",
    ],
    technical: [
      "DELEGATECALL to a contract that has been selfdestructed → calls revert / fallback returns empty.",
      "Mitigation: never expose selfdestruct on shared infrastructure; freeze admin via timelock + multisig + role separation.",
    ],
    tx_hashes: ["0x0570400e38e50c70fa25d3aac496f6e937a6bf7b08e45bcf22e6fa6f3e2afbe6"],
    layer: "access-control",
    attack_vector: "self-destruct of shared delegatecall target",
    references: [
      { title: "OpenZeppelin — Parity Wallet Hack Reloaded", url: "https://blog.openzeppelin.com/parity-wallet-hack-reloaded" },
    ],
  },
};

// ──────────────────────────────────────────────────────────────────────────
// Synthetic incidents prepended to the API list
// ──────────────────────────────────────────────────────────────────────────

export const INJECTED_INCIDENTS: Incident[] = [
  {
    id: -1, // negative ids = client-side only
    vulnerability_class: "cross-chain-trust",
    tx_hash: "0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222",
    loss_usd: 292_000_000,
    incident_date: "2026-04-18",
    source_url: "https://defiprime.com/kelpdao-rseth-exploit",
    description:
      "Kelp DAO rsETH bridge exploit. Attackers tricked a 1-of-1 LayerZero DVN into approving a phantom mint of 116,500 rsETH; dumped through Aave & Fluid for ~$292M.",
  },
];

// Lookup helper — Kelp's curated entry lives under a synthetic id; older
// historical rows are keyed by their tx_hash directly.
const KELP_TX = "0x1ae232da212c45f35c1525f851e4c41d529bf18af862d9ce9fd40bf709db4222";

export function detailFor(incident: Incident): IncidentDetail | null {
  if (incident.tx_hash === KELP_TX) {
    return INCIDENT_DETAILS["kelp-rseth-2026-04-18"];
  }
  if (incident.tx_hash && INCIDENT_DETAILS[incident.tx_hash]) {
    return INCIDENT_DETAILS[incident.tx_hash];
  }
  return null;
}
