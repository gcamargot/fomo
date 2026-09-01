# 🛡️ FOMO Smart Contract Security Suite & Autonomous Watcher

FOMO is an on-chain smart contract security auditing, automated extraction, and vulnerability triage platform supporting **EVM ecosystems** (Base, Ethereum, Arbitrum, Optimism, Polygon, BSC) and **Solana**.

Packaged as a production Docker product with continuous scanning daemons, automated static analysis (Slither & AST detectors), Foundry test simulations, and seamless CI/CD integration for self-hosted homelab deployment.

---

## 🐳 Quickstart with Docker & Docker Compose

### 1. Configure Environment
Copy the example configuration:
```bash
cp .env.example .env
```
*(Optional: edit `.env` with custom RPC URLs or block explorer API keys)*

### 2. Launch Suite in Background (Daemon Mode)
```bash
docker compose up -d
```
This automatically launches:
* `token_scanner_daemon.py`: Scans newly verified contracts across Base, Arbitrum, Ethereum, and Solana.
* `dormant_monitor_daemon.py`: Monitors dormant vulnerable contracts for balance changes and activation.

### 3. Check Live Logs & Status
```bash
docker compose logs -f
docker compose ps
```

### 4. Execute Ad-Hoc CLI Commands Inside Container
```bash
# Scan a single wallet's contract interactions
docker compose run --rm fomo python3 contract_extractor.py --wallet 0x5D06A812a8d5F301fDb4101E8F39eA73be39eEE4 --chain base

# Scan a single contract and run Slither
docker compose run --rm fomo python3 contract_extractor.py --contract 0x2626664c2603336E57B271c5C0b26F421741e481 --chain base --auto-scan

# Query real-time statistics (JSON format)
docker compose run --rm fomo python3 token_scanner_daemon.py --stats --json
```

---

## 🏗️ Architecture & Key Components

| Component | Description |
| :--- | :--- |
| [`token_scanner_daemon.py`](file:///home/nahtao97/fomo/token_scanner_daemon.py) | Autonomous monitoring daemon, static AST auditor, and triage card generator. |
| [`dormant_monitor_daemon.py`](file:///home/nahtao97/fomo/dormant_monitor_daemon.py) | Balance watcher for dormant vulnerable contracts. |
| [`contract_extractor.py`](file:///home/nahtao97/fomo/contract_extractor.py) | CLI orchestrator for single contract/wallet extraction, classification, and Slither scans. |
| [`classifier.py`](file:///home/nahtao97/fomo/classifier.py) | Smart contract taxonomy classifier (ERC20, ERC4626, Routers, Pools, Lending, Proxies). |
| [`analyzer.py`](file:///home/nahtao97/fomo/analyzer.py) | Slither analysis runner and markdown security report generator. |
| [`dataset_metrics.py`](file:///home/nahtao97/fomo/dataset_metrics.py) | Aggregate dataset statistics generator for research and publication. |
| [`simulations/`](file:///home/nahtao97/fomo/simulations/) | Foundry (`forge test`) test suites for slippage frontrunning, fee friction, and vault inflation attacks. |

---

## 🧪 Local Development & Testing

### Python Tests & Linter
```bash
# Run pytest test suite
pytest -v

# Run code style & quality checks
ruff check .
```

### Smart Contract Simulation Tests (Foundry)
```bash
cd simulations
forge test -v
```

---

## 🔄 CI/CD Pipeline

The project is equipped with automated GitHub Actions workflows:

### 1. Continuous Integration (`.github/workflows/ci.yml`)
Runs on every Pull Request and branch push:
* **Lint:** Runs `ruff check .`
* **Python Tests:** Executes `pytest` with Solidity compiler setup.
* **Foundry Tests:** Compiles and runs `forge test` in `simulations/`.
* **Docker Build Check:** Verifies that the Docker container builds without errors.

### 2. Continuous Deployment (`.github/workflows/cd.yml`)
Triggers on merge to `main`:
1. **Build & Push:** Builds multi-arch Docker image and pushes to GitHub Container Registry: `ghcr.io/gcamargot/fomo:latest`.
2. **Homelab Deploy:** Connects to your self-hosted GitHub Actions runner in your homelab, runs `docker compose pull`, and restarts the containers seamlessly (`docker compose up -d`).

---

## ⚙️ Homelab Self-Hosted Runner Setup Guide

To deploy automatically to your homelab on merge to `main`:

1. In GitHub, navigate to: **Settings $\rightarrow$ Actions $\rightarrow$ Runners $\rightarrow$ New self-hosted runner**.
2. Select your OS (e.g. Linux x64/ARM64) and follow the download/configuration commands on your homelab server:
   ```bash
   # Download and configure runner
   mkdir actions-runner && cd actions-runner
   curl -o actions-runner-linux-x64-...tar.gz -L https://github.com/actions/runner/releases/download/...
   tar xzf ./actions-runner-linux-x64-...tar.gz
   ./config.sh --url https://github.com/gcamargot/fomo --token <REGISTRATION_TOKEN>
   ```
3. Install and run as a systemd service:
   ```bash
   sudo ./svc.sh install
   sudo ./svc.sh start
   ```
4. Ensure the runner user has permission to run `docker compose` (`sudo usermod -aG docker $USER`).

---

## 🛡️ GitHub Branch Protection Protocol

To protect the `main` branch from direct commits and broken builds:

1. Go to: **Settings $\rightarrow$ Rules $\rightarrow$ Rulesets** (or **Branches $\rightarrow$ Add branch protection rule**).
2. Rule Target: `main`
3. Enable the following protections:
   - [x] **Require a pull request before merging** (Require approvals: optional / 1).
   - [x] **Require status checks to pass before merging**:
     - `Lint & Code Style (Ruff)`
     - `Python Test Suite (pytest)`
     - `Smart Contract Simulation Tests (Foundry)`
     - `Docker Image Build Validation`
   - [x] **Require linear history**
   - [x] **Block force pushes** & **Do not allow deletions**
