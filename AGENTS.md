# 🤖 Agent Guide & Operational Protocol: FOMO Smart Contract Security Suite

Welcome, Agent. This workspace is a specialized **On-Chain Smart Contract Security Auditing & Empirical Research Environment**. It is designed to automatically extract, classify, monitor, and triage smart contract vulnerabilities across EVM chains (Base, Ethereum, Arbitrum) and Solana.

---

## ⚡ 1. Autonomous Daemon Operation

The background daemon (`token_scanner_daemon.py`) is designed to run autonomously and continuously without manual intervention:

* **What it does:** Polls block explorers and DEX factories for newly verified smart contracts, downloads source code, extracts ABIs and metadata, classifies contracts into taxonomic categories, and executes static AST + Slither security detectors.
* **Threat Model Classification:**
  * **Owner-Centralization Risks** (Dynamic taxes, whitelist honeypots, arbitrary mints) $\rightarrow$ Logged to SQLite for empirical dataset metrics.
  * **User-Exploitable Vulnerabilities** (Zero-slippage liquidation `amountOutMin = 0`, arbitrary calls, inflation attacks) $\rightarrow$ Emits an alert and generates an actionable **Triage Card** in `./contracts/triage_queue/`.

### Starting / Managing the Daemon:
```bash
# Run in background (multi-day collection):
nohup python3 token_scanner_daemon.py --daemon --interval 60 --chain base > scanner.log 2>&1 &

# Run a single audit cycle (immediate polling):
python3 token_scanner_daemon.py --once

# Directly scan a specific target contract address:
python3 token_scanner_daemon.py --scan-address 0xAC1Bd2486aAf3B5C0fc3Fd868558b082a531b2b4
```

---

## 📊 2. Pipeline dashboard (`--stats`)

`--stats` is the live profit-pipeline snapshot (not detector prevalence).

```bash
python3 token_scanner_daemon.py --stats --json
python3 token_scanner_daemon.py --stats
```

JSON (nested dashboard is canonical; a few aliases remain for old callers):

```json
{
  "corpus": {"total": 8990, "verified": 7988, "by_chain": {"base": 839}},
  "hits": {
    "pending_review": 1,
    "confirmed": 1,
    "profit_pass": 1,
    "min_profit_eth": 0.05,
    "queue": [{"path": ".../triage_base_0xabc.md", "address": "0xabc", "chain": "base", "expected_profit_eth": 0.4}]
  },
  "watchlist": {"near_miss": 3, "sleeping_tax": 40, "unfunded_drain": 12},
  "factory": {"no_source": 4, "dust": 1, "actionable": 0, "total": 5},
  "inventory": {"public_swapback": 20, "zero_slippage": 2},
  "top_expected_profit": []
}
```

How to read it:

- **hits.pending_review** — `.md` cards still in `contracts/triage_queue/` (review these).
- **hits.profit_pass** — rows with `expected_profit_eth >= 0.05`.
- **watchlist** — not yet actionable (near-miss / sleeping swapBack / unfunded drain).
- **factory** — new WETH pairs from `PairCreated` (source vs dust vs estimate PASS).
- Owner-centralization and per-detector prevalence are **not** in `--stats`. Use `dataset_metrics.py` for the academic corpus.

---

## 🛡️ 3. Triage Queue Workflow (`./contracts/triage_queue/`)

When a contract exhibits a **User-Exploitable** vulnerability, a triage card is created at:
`./contracts/triage_queue/triage_<chain>_<address>.md`

### Agent Protocol for Assisting with Triage:
1. **Read Pending Cards:** Read the files listed in `triage_queue_files`.
2. **Inspect Code Snippet:** Verify the code lines containing `swapExactTokensForETH*(..., 0, ...)` or unconstrained external calls.
3. **Verify On-Chain Liquidity:** Check whether the pool exists and whether the contract accumulates tokens in its balance.
4. **Update Verdict:** Help the researcher fill the checklist:
   - `[x] True Positive (TP)` vs `[ ] False Positive (FP)`
   - Assign Confidence: `High / Medium / Low`
   - Document research notes for inclusion in the academic paper.

---

## 📁 4. Key Files & Workspace Architecture

| File / Directory | Purpose |
| :--- | :--- |
| [`token_scanner_daemon.py`](file:///home/nahtao97/fomo/token_scanner_daemon.py) | Autonomous monitoring daemon, static AST auditor, and triage card generator. |
| [`contract_extractor.py`](file:///home/nahtao97/fomo/contract_extractor.py) | CLI orchestrator for single contract/wallet extraction, classification, and Slither scans. |
| [`evm_extractor.py`](file:///home/nahtao97/fomo/evm_extractor.py) | Multi-chain EVM connector (Base, Ethereum, Arbitrum, BSC, Optimism, Polygon). |
| [`solana_extractor.py`](file:///home/nahtao97/fomo/solana_extractor.py) | Solana RPC extractor, program parser, and `.so` ELF binary dumper. |
| [`classifier.py`](file:///home/nahtao97/fomo/classifier.py) | Taxonomy engine (ERC20, DEX_ROUTER, DEX_POOL, VAULT, PROXY, LENDING). |
| [`dataset_metrics.py`](file:///home/nahtao97/fomo/dataset_metrics.py) | Compiles aggregate dataset statistics into [`DATASET_METRICS.md`](file:///home/nahtao97/fomo/contracts/DATASET_METRICS.md). |
| [`simulations/`](file:///home/nahtao97/fomo/simulations/) | Foundry (`forge test`) reproducible simulation test suite for slippage and inflation attacks. |
| [`contracts/token_research_dataset.db`](file:///home/nahtao97/fomo/contracts/token_research_dataset.db) | SQLite database persisting all scanned tokens and vulnerability flags. |
| [`contracts/triage_queue/`](file:///home/nahtao97/fomo/contracts/triage_queue/) | Active queue of User-Exploitable vulnerability cards. |

---

## ⚙️ 5. Environment & Toolchain Settings

* **Custom Shell Profile:** `source ~/.bashrc_fomo` loads user binaries (`forge`, `cast`, `solana`, `slither`, `pip`).
* **Python Dependencies:** Run with standard Python 3.12 (`python3`).
* **Solidity Compiler:** Managed via `solc-select` (default active: `0.8.20`).
