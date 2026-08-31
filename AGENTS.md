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

## 📊 2. How to Query Stats Programmatically (JSON API)

Agents should query the database stats using the `--stats --json` flag for easy, deterministic parsing:

```bash
python3 token_scanner_daemon.py --stats --json
```

### JSON Schema Output:
```json
{
  "total_scanned": 25,
  "verified_contracts": 20,
  "user_exploitable_count": 5,
  "user_exploitable_percentage": 25.0,
  "metrics": {
    "zero_slippage_liquidation": {
      "count": 5,
      "prevalence_percent": 25.0
    },
    "conditional_honeypot": {
      "count": 8,
      "prevalence_percent": 40.0
    },
    "dynamic_taxes": {
      "count": 12,
      "prevalence_percent": 60.0
    }
  },
  "pending_triage_cards_count": 5,
  "triage_queue_files": [
    "/home/nahtao97/fomo/contracts/triage_queue/triage_base_0xac1bd2486aaf3b5c0fc3fd868558b082a531b2b4.md"
  ]
}
```

*For human-readable Rich table output, omit `--json`:*
```bash
python3 token_scanner_daemon.py --stats
```

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
