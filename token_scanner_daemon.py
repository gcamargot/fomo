#!/usr/bin/env python3
"""
Continuous On-Chain Token Security Scanner & Triage Queue Generator
===================================================================
Monitors newly created token pairs and verified contracts on Base / EVM,
performs automated vulnerability auditing, assesses whether a vulnerability is
USER-EXPLOITABLE (positive financial payoff for an external user), and generates
structured Triage Cards (.md) for manual verification and False/True Positive triage.
"""

import os
import sys
import time
import json
import sqlite3
import re
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from evm_extractor import EVMExtractor
from classifier import ContractClassifier
from analyzer import ContractAnalyzer

console = Console()

DB_PATH = "./contracts/token_research_dataset.db"
TRIAGE_DIR = "./contracts/triage_queue"

class TokenScannerDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                address TEXT PRIMARY KEY,
                name TEXT,
                symbol TEXT,
                chain TEXT,
                compiler TEXT,
                category TEXT,
                verified BOOLEAN,
                first_seen_timestamp TEXT,
                is_user_exploitable BOOLEAN,
                has_zero_slippage BOOLEAN,
                has_dynamic_taxes BOOLEAN,
                has_conditional_honeypot BOOLEAN,
                has_unlimited_mint BOOLEAN,
                slither_high INTEGER,
                slither_medium INTEGER,
                slither_low INTEGER,
                triage_file_path TEXT,
                raw_metadata TEXT
            )
            """)
            conn.commit()

    def is_scanned(self, address: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM tokens WHERE address = ?", (address.lower(),))
            return cursor.fetchone() is not None

    def save_scan(self, data: Dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT OR REPLACE INTO tokens (
                address, name, symbol, chain, compiler, category, verified,
                first_seen_timestamp, is_user_exploitable, has_zero_slippage,
                has_dynamic_taxes, has_conditional_honeypot, has_unlimited_mint,
                slither_high, slither_medium, slither_low, triage_file_path, raw_metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["address"].lower(),
                data.get("name", "Unknown"),
                data.get("symbol", "N/A"),
                data.get("chain", "base"),
                data.get("compiler", "Unknown"),
                data.get("category", "CUSTOM_LOGIC"),
                data.get("verified", False),
                data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                data.get("is_user_exploitable", False),
                data.get("has_zero_slippage", False),
                data.get("has_dynamic_taxes", False),
                data.get("has_conditional_honeypot", False),
                data.get("has_unlimited_mint", False),
                data.get("slither_high", 0),
                data.get("slither_medium", 0),
                data.get("slither_low", 0),
                data.get("triage_file_path", None),
                json.dumps(data.get("raw_metadata", {}))
            ))
            conn.commit()

class StaticVulnerabilityAuditor:
    """
    Performs static pattern audits and extracts contextual code snippets.
    """

    @staticmethod
    def audit_source(source_text: str) -> Tuple[Dict[str, bool], List[Dict]]:
        findings = {
            "has_zero_slippage": False,
            "has_dynamic_taxes": False,
            "has_conditional_honeypot": False,
            "has_unlimited_mint": False,
        }
        evidence_list = []

        # 1. Zero Slippage Liquidation (USER EXPLOITABLE)
        slippage_match = re.search(r"swapExactTokensForETH\w*\s*\([^,]+,\s*0\s*,", source_text)
        if slippage_match:
            findings["has_zero_slippage"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, slippage_match.start())
            evidence_list.append({
                "type": "ZERO_SLIPPAGE_LIQUIDATION",
                "user_exploitable": True,
                "title": "Falta de Protección de Slippage en Auto-Liquidación (`amountOutMin = 0`)",
                "severity": "HIGH",
                "exploiter": "Cualquier Usuario / Bot MEV / Flash Loan",
                "victim": "Tesorería del Contrato (Tokens acumulados de comisiones)",
                "payoff": "Ganancia Neta en ETH extraída de la venta forzada con deslizamiento máximo.",
                "snippet": snippet
            })

        # 2. Conditional Honeypot (OWNER RESTRICTION / NOT USER PROFITABLE)
        honeypot_match = re.search(r"require\s*\([^)]*(?:limited|_is\w+|isWhitelisted|_sniper)[^)]*\)", source_text, re.IGNORECASE)
        if honeypot_match:
            findings["has_conditional_honeypot"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, honeypot_match.start())
            evidence_list.append({
                "type": "CONDITIONAL_HONEYPOT",
                "user_exploitable": False,
                "title": "Restricción de Transferencia Condicional (Anti-Sniper / Honeypot)",
                "severity": "MEDIUM",
                "exploiter": "Owner / Deployer",
                "victim": "Compradores generales",
                "payoff": "Restricción de venta o monopolio inicial de compra (no extrae fondos externos directamente).",
                "snippet": snippet
            })

        # 3. Dynamic Fee Hijack (OWNER CENTRALIZATION)
        tax_match = re.search(r"function\s+set\w*Fee\w*\s*\(", source_text, re.IGNORECASE)
        if tax_match:
            findings["has_dynamic_taxes"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, tax_match.start())
            evidence_list.append({
                "type": "DYNAMIC_FEE_HIJACK",
                "user_exploitable": False,
                "title": "Modificación Dinámica de Comisiones (Taxes)",
                "severity": "LOW / MEDIUM",
                "exploiter": "Owner",
                "victim": "Traders",
                "payoff": "Aumento arbitrario de comisiones de compra/venta.",
                "snippet": snippet
            })

        # 4. Arbitrary Minting (OWNER CENTRALIZATION)
        mint_match = re.search(r"function\s+mint\s*\([^)]*\)\s*(?:public|external)[^{]*onlyOwner", source_text)
        if mint_match:
            findings["has_unlimited_mint"] = True
            snippet = StaticVulnerabilityAuditor._extract_snippet(source_text, mint_match.start())
            evidence_list.append({
                "type": "UNLIMITED_MINT",
                "user_exploitable": False,
                "title": "Emisión Ilimitada Oculta de Tokens",
                "severity": "HIGH",
                "exploiter": "Owner",
                "victim": "Holders (Dilución del valor)",
                "payoff": "Creación arbitraria de suministro.",
                "snippet": snippet
            })

        return findings, evidence_list

    @staticmethod
    def _extract_snippet(source: str, index: int, context_lines: int = 6) -> str:
        lines = source[:index].split("\n")
        start_line_num = max(0, len(lines) - context_lines)
        all_lines = source.split("\n")
        end_line_num = min(len(all_lines), len(lines) + context_lines)
        return "\n".join(f"{i+1}: {all_lines[i]}" for i in range(start_line_num, end_line_num))

class TriageReportGenerator:
    """
    Generates structured Markdown triage documents for researcher manual verification.
    """

    @staticmethod
    def generate_triage_file(contract_data: Dict, user_exploits: List[Dict], output_dir: str = TRIAGE_DIR) -> str:
        os.makedirs(output_dir, exist_ok=True)
        addr = contract_data["address"].lower()
        chain = contract_data.get("chain", "base")
        name = contract_data.get("name", "Unknown")
        
        file_name = f"triage_{chain}_{addr}.md"
        full_path = os.path.join(output_dir, file_name)

        md = []
        md.append(f"# 🛡️ Triage Card: User-Exploitable Vulnerability Assessment\n")
        md.append(f"**Contract Name:** `{name}`  \n")
        md.append(f"**Address:** [`{addr}`](https://basescan.org/address/{addr})  \n")
        md.append(f"**Blockchain:** `{chain.upper()}` | **Compiler:** `{contract_data.get('compiler', 'Unknown')}`  \n")
        md.append(f"**Category:** `{contract_data.get('category', 'CUSTOM_LOGIC')}`  \n")
        md.append(f"**Detected Timestamp:** `{datetime.now(timezone.utc).isoformat()}`  \n\n")

        md.append("## 1. Executive Vulnerability Summary\n")
        md.append("Esta tarjeta fue generada automáticamente porque se detectó al menos una vulnerabilidad con **retorno financiero directo para un usuario/atacante externo** ($\text{ROI} > 0$).\n\n")

        for idx, exp in enumerate(user_exploits, 1):
            md.append(f"### {idx}. [{exp['severity']}] {exp['title']}\n")
            md.append(f"* **¿Es explotable por un usuario común?:** `SÍ` (No requiere permisos de administrador ni de owner).\n")
            md.append(f"* **Perfil del Atacante:** {exp['exploiter']}\n")
            md.append(f"* **Víctima Afectada:** {exp['victim']}\n")
            md.append(f"* **Beneficio / Payoff Esperado:** {exp['payoff']}\n\n")
            md.append(f"#### Fragmento de Código Relevante:\n```solidity\n{exp['snippet']}\n```\n")

        md.append("\n---\n")
        md.append("## 2. Checklist de Verificación y Triage Manual (Researcher Evaluation)\n")
        md.append("Completa esta sección para confirmar si el hallazgo es un **True Positive (TP)** o **False Positive (FP)** para tu paper:\n\n")
        md.append("- [ ] **Paso 1: Verificación de Parámetros On-Chain**  \n")
        md.append("  - ¿El contrato acumula comisiones en su propio balance (`balanceOf(address(this))`)?  \n")
        md.append("  - ¿El umbral `swapTokensAtAmount` es alcanzable con el volumen actual de transacciones?  \n\n")
        md.append("- [ ] **Paso 2: Confirmación de Falta de Límite de Slippage**  \n")
        md.append("  - ¿El segundo parámetro en `swapExactTokensForETH` es literalmente `0` o no utiliza oráculo TWAP previo?  \n\n")
        md.append("- [ ] **Paso 3: Análisis de Liquidez del Pool Asociado**  \n")
        md.append("  - ¿Existe un par AMM desplegado (ej. Uniswap V2 / Aerodrome)?  \n")
        md.append("  - Reservas estimadas del pool: `________ ETH`  \n\n")
        md.append("### Veredicto del Triage:\n")
        md.append("- **Resultado:** `[ ] True Positive` | `[ ] False Positive` | `[ ] Low Severity / Inactive`  \n")
        md.append("- **Confianza:** `[ ] Alta` | `[ ] Media` | `[ ] Baja`  \n")
        md.append("- **Notas del Investigador:**  \n")
        md.append("  > _Escribe aquí tus observaciones para incluir en la tabla de resultados empíricos del paper._\n")

        content = "\n".join(md)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        return full_path

class TokenScannerDaemon:
    def __init__(self, chain: str = "base", output_dir: str = "./contracts"):
        self.chain = chain
        self.output_dir = output_dir
        self.extractor = EVMExtractor(chain=chain)
        self.db = TokenScannerDB()
        self.analyzer = ContractAnalyzer()

    def fetch_recent_verified_contracts(self, limit: int = 25) -> List[str]:
        bs_v2 = self.extractor.config.get("blockscout_v2")
        if not bs_v2:
            return []

        url = f"{bs_v2}/smart-contracts"
        try:
            resp = self.extractor.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                addresses = []
                for item in items[:limit]:
                    addr = item.get("address", {}).get("hash")
                    if addr:
                        addresses.append(addr.lower())
                return addresses
        except Exception:
            pass
        return []

    def scan_contract(self, address: str) -> Optional[Dict]:
        address = address.lower().strip()
        if self.db.is_scanned(address):
            return None

        console.print(f"[bold cyan]🔍 Scanning contract:[/] {address}")
        verified, path, meta = self.extractor.save_contract(address, self.output_dir)

        scan_result = {
            "address": address,
            "name": meta.get("contract_name", "Unknown"),
            "chain": self.chain,
            "compiler": meta.get("compiler_version", "Unknown"),
            "category": meta.get("category", "CUSTOM_LOGIC"),
            "verified": verified,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "is_user_exploitable": False,
            "has_zero_slippage": False,
            "has_dynamic_taxes": False,
            "has_conditional_honeypot": False,
            "has_unlimited_mint": False,
            "slither_high": 0,
            "slither_medium": 0,
            "slither_low": 0,
            "triage_file_path": None,
            "raw_metadata": meta
        }

        if verified:
            src_dir = os.path.join(path, "src")
            all_source = ""
            for root, _, files in os.walk(src_dir):
                for f in files:
                    if f.endswith(".sol"):
                        try:
                            with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as sol_file:
                                all_source += "\n" + sol_file.read()
                        except Exception:
                            pass

            findings, evidence_list = StaticVulnerabilityAuditor.audit_source(all_source)
            scan_result.update(findings)

            # Filter for user-exploitable vulnerabilities
            user_exploits = [e for e in evidence_list if e.get("user_exploitable", False)]
            
            if user_exploits:
                scan_result["is_user_exploitable"] = True
                triage_path = TriageReportGenerator.generate_triage_file(scan_result, user_exploits)
                scan_result["triage_file_path"] = triage_path
                
                console.print(Panel(
                    f"[bold red]⚠️ USER-EXPLOITABLE VULNERABILITY DETECTED![/]\n\n"
                    f"[bold green]Contract:[/] {meta.get('contract_name')} ({address})\n"
                    f"[bold yellow]Findings:[/] {len(user_exploits)} user-exploitable vector(s)\n"
                    f"[bold cyan]Triage Card Created:[/] [underline]{triage_path}[/]",
                    title="Action Required: Triage Queue Entry",
                    border_style="red"
                ))

            # Run Slither static triage
            try:
                report = self.analyzer.run_slither(src_dir if os.path.exists(src_dir) else path, output_report_dir=path)
                sum_rep = report.get("findings_summary", {})
                scan_result["slither_high"] = sum_rep.get("High", 0)
                scan_result["slither_medium"] = sum_rep.get("Medium", 0)
                scan_result["slither_low"] = sum_rep.get("Low", 0)
            except Exception:
                pass

        self.db.save_scan(scan_result)
        return scan_result

    def run_poll_cycle(self):
        contracts = self.fetch_recent_verified_contracts(limit=30)
        new_count = 0
        for addr in contracts:
            if not self.db.is_scanned(addr):
                self.scan_contract(addr)
                new_count += 1
                time.sleep(1)
        return new_count

    def run_continuous_monitoring(self, interval_seconds: int = 60):
        console.print(f"[bold green]🚀 Starting Continuous Security & Triage Scanner Daemon on {self.chain.upper()}...[/]")
        console.print(f"[dim]Triage queue directory: {os.path.abspath(TRIAGE_DIR)}[/]")
        console.print(f"[dim]Polling every {interval_seconds}s. Press Ctrl+C to stop.[/]\n")

        while True:
            try:
                new_tokens = self.run_poll_cycle()
                if new_tokens > 0:
                    console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} - Processed {new_tokens} new contracts.[/]")
                time.sleep(interval_seconds)
            except KeyboardInterrupt:
                console.print("\n[yellow]Daemon stopped by user.[/]")
                break
            except Exception as e:
                console.print(f"[red]Daemon error: {e}[/]")
                time.sleep(10)

def display_db_stats(as_json: bool = False):
    if not os.path.exists(DB_PATH):
        if as_json:
            print(json.dumps({"error": "No database found", "total_scanned": 0}))
        else:
            console.print("[yellow]No database found yet.[/]")
        return

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tokens")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tokens WHERE is_user_exploitable = 1")
        user_exploitable_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_zero_slippage = 1")
        slippage_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_conditional_honeypot = 1")
        honeypot_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tokens WHERE has_dynamic_taxes = 1")
        tax_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tokens WHERE verified = 1")
        verified_count = cursor.fetchone()[0]

    tot_calc = max(1, verified_count)

    pending_cards = []
    if os.path.exists(TRIAGE_DIR):
        pending_cards = [os.path.abspath(os.path.join(TRIAGE_DIR, f)) for f in os.listdir(TRIAGE_DIR) if f.endswith(".md")]

    if as_json:
        stats_payload = {
            "total_scanned": total,
            "verified_contracts": verified_count,
            "user_exploitable_count": user_exploitable_count,
            "user_exploitable_percentage": round((user_exploitable_count / tot_calc) * 100, 2),
            "metrics": {
                "zero_slippage_liquidation": {
                    "count": slippage_count,
                    "prevalence_percent": round((slippage_count / tot_calc) * 100, 2)
                },
                "conditional_honeypot": {
                    "count": honeypot_count,
                    "prevalence_percent": round((honeypot_count / tot_calc) * 100, 2)
                },
                "dynamic_taxes": {
                    "count": tax_count,
                    "prevalence_percent": round((tax_count / tot_calc) * 100, 2)
                }
            },
            "pending_triage_cards_count": len(pending_cards),
            "triage_queue_files": pending_cards
        }
        print(json.dumps(stats_payload, indent=2))
        return

    table = Table(title="Multi-Day Token Security Dataset & Triage Summary")
    table.add_column("Vulnerability Metric", style="yellow")
    table.add_column("Detected Count", style="red bold", justify="right")
    table.add_column("Prevalence (%)", style="cyan", justify="right")

    table.add_row("Total Scanned Contracts", str(total), "100.0%")
    table.add_row("Verified Source Contracts", str(verified_count), f"{(verified_count/max(1,total))*100:.1f}%")
    table.add_row("🚨 USER-EXPLOITABLE (Triage Queue)", str(user_exploitable_count), f"{(user_exploitable_count/tot_calc)*100:.1f}%")
    table.add_row("Zero Slippage Liquidation (`amountOutMin=0`)", str(slippage_count), f"{(slippage_count/tot_calc)*100:.1f}%")
    table.add_row("Conditional Honeypot / Whitelists", str(honeypot_count), f"{(honeypot_count/tot_calc)*100:.1f}%")
    table.add_row("Dynamic Fee / Tax Manipulations", str(tax_count), f"{(tax_count/tot_calc)*100:.1f}%")

    console.print(table)

    if pending_cards:
        console.print(f"\n[bold magenta]📁 Pending Triage Cards for Researcher Review ({len(pending_cards)}):[/]")
        for c in pending_cards:
            console.print(f"  • [cyan]{c}[/]")

def main():
    parser = argparse.ArgumentParser(description="Multi-day Token Security Scanner & Triage Queue Generator")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous background polling mode")
    parser.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (default: 60)")
    parser.add_argument("--once", action="store_true", help="Run a single scan cycle and exit")
    parser.add_argument("--scan-address", help="Directly scan and generate triage card for a specific contract address")
    parser.add_argument("--stats", action="store_true", help="Display aggregated statistical summary and list triage queue")
    parser.add_argument("--json", action="store_true", help="Output stats and findings in machine-readable JSON format")
    parser.add_argument("--chain", default="base", help="Chain to monitor (default: base)")

    args = parser.parse_args()

    if args.stats:
        display_db_stats(as_json=args.json)
        return

    daemon = TokenScannerDaemon(chain=args.chain)

    if args.scan_address:
        daemon.scan_contract(args.scan_address)
        display_db_stats(as_json=args.json)
    elif args.once:
        if not args.json:
            console.print("[cyan]Running single poll cycle...[/]")
        daemon.run_poll_cycle()
        display_db_stats(as_json=args.json)
    elif args.daemon:
        daemon.run_continuous_monitoring(interval_seconds=args.interval)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
