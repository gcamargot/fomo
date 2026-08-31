#!/usr/bin/env python3
"""
FOMO Smart Contract Extractor & Vulnerability Dataset Builder
============================================================
Tool for extracting, downloading, classifying, and analyzing smart contracts
interacted with by wallets across EVM (Base, Ethereum, Arbitrum, BSC) and Solana.
"""

import argparse
import os
import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from evm_extractor import EVMExtractor, EXPLORER_CONFIGS
from solana_extractor import SolanaExtractor, KNOWN_PROGRAMS
from classifier import ContractClassifier
from analyzer import ContractAnalyzer
from dataset_metrics import DatasetMetricsGenerator

console = Console()

CATEGORIES_LIST = [
    "ALL", "ERC20_TOKEN", "ERC721_NFT", "ERC1155_MULTI_TOKEN",
    "ERC4626_VAULT", "DEX_ROUTER_AGGREGATOR", "DEX_LIQUIDITY_POOL",
    "LENDING_BORROWING", "SMART_WALLET_ACCOUNT_ABSTRACTION",
    "GOVERNANCE_TIMELOCK", "PROXY_FACTORY", "CUSTOM_LOGIC"
]

def process_evm_wallet(wallet: str, chain: str, output_dir: str, api_key: str, auto_scan: bool, category_filter: str = "ALL"):
    console.print(f"[bold cyan]🔍 Inspecting EVM Wallet:[/] {wallet} on [green]{chain.upper()}[/]")
    if category_filter != "ALL":
        console.print(f"[bold yellow]Filter Active:[/] Only downloading category [magenta]{category_filter}[/]")
    
    extractor = EVMExtractor(chain=chain, api_key=api_key)
    
    with console.status("[bold yellow]Querying transaction history & contract interactions...[/]"):
        contracts = extractor.get_wallet_contract_interactions(wallet)

    if not contracts:
        console.print("[yellow]⚠️  No contract interactions found. (Wallet may be inactive or on another chain).[/]")
        return

    console.print(f"[bold green]✓ Found {len(contracts)} unique contract interactions![/]\n")

    table = Table(title=f"Discovered Contracts on {chain.upper()}")
    table.add_column("#", style="dim", width=4)
    table.add_column("Contract Address", style="cyan")
    table.add_column("Category", style="yellow")
    table.add_column("Status", style="magenta")

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task("[cyan]Downloading & classifying...", total=len(contracts))
        
        for idx, addr in enumerate(contracts, 1):
            progress.update(task, description=f"Processing {addr[:10]}... ({idx}/{len(contracts)})")
            verified, path, meta = extractor.save_contract(addr, output_dir)
            cat = meta.get("category", "CUSTOM_LOGIC")

            # Check category filter
            if category_filter != "ALL" and cat != category_filter:
                progress.advance(task)
                continue

            status_str = f"[green]Verified: {meta.get('contract_name')}[/]" if verified else "[yellow]Unverified (Bytecode saved)[/]"
            if meta.get("proxy") and meta.get("implementation"):
                status_str += f"\n[blue]↳ Proxy to: {meta.get('implementation')[:10]}...[/]"
                # Download implementation as well
                extractor.save_contract(meta["implementation"], output_dir)
            
            table.add_row(str(idx), addr, f"[bold]{cat}[/]", status_str)
            results.append((addr, verified, path, meta))
            progress.advance(task)

    console.print(table)
    console.print(f"\n[bold green]📁 Contracts saved to:[/] [underline]{os.path.abspath(output_dir)}[/]")

    if auto_scan and results:
        run_batch_analysis(results, output_dir)

def process_evm_contract(contract: str, chain: str, output_dir: str, api_key: str, auto_scan: bool):
    console.print(f"[bold cyan]📥 Fetching EVM Contract:[/] {contract} on [green]{chain.upper()}[/]")
    extractor = EVMExtractor(chain=chain, api_key=api_key)
    
    with console.status("[bold yellow]Downloading source & metadata...[/]"):
        verified, path, meta = extractor.save_contract(contract, output_dir)

    impl_str = f" -> {meta.get('implementation')}" if meta.get('implementation') else ""
    if verified:
        console.print(Panel(
            f"[bold green]Contract Name:[/] {meta.get('contract_name')}\n"
            f"[bold yellow]Classification Category:[/] [bold]{meta.get('category')}[/] (confidence: {meta.get('classification_confidence', 'N/A')})\n"
            f"[bold cyan]Tags:[/] {', '.join(meta.get('tags', []))}\n"
            f"[bold green]Compiler:[/] {meta.get('compiler_version')}\n"
            f"[bold green]Optimization:[/] {meta.get('optimization')} (runs: {meta.get('runs')})\n"
            f"[bold green]Proxy:[/] {meta.get('proxy')}{impl_str}\n"
            f"[bold green]Directory:[/] {path}",
            title="Smart Contract Profile & Classification",
            border_style="green"
        ))
        if meta.get("proxy") and meta.get("implementation"):
            console.print(f"[cyan]Downloading implementation contract {meta['implementation']}...[/]")
            extractor.save_contract(meta["implementation"], output_dir)

        if auto_scan:
            analyzer = ContractAnalyzer()
            src_dir = os.path.join(path, "src")
            target = src_dir if os.path.exists(src_dir) else path
            console.print(f"\n[bold magenta]🔬 Running Slither Static Analysis on {target}...[/]")
            report = analyzer.run_slither(target, output_report_dir=path)
            md_out = os.path.join(path, "SECURITY_REPORT.md")
            analyzer.generate_markdown_report(report, md_out)
            console.print(f"[bold green]✓ Security Report generated:[/] {md_out}")
    else:
        console.print(f"[yellow]⚠️  Contract is not verified. Saved runtime bytecode in {path}[/]")

def process_solana_wallet(wallet: str, output_dir: str, rpc_url: str):
    console.print(f"[bold cyan]🔍 Inspecting Solana Wallet:[/] {wallet}")
    extractor = SolanaExtractor(rpc_url=rpc_url)
    
    with console.status("[bold yellow]Analyzing Solana transactions & program calls...[/]"):
        data = extractor.inspect_wallet_interactions(wallet)

    programs = data.get("programs", [])
    tokens = data.get("token_mints", [])

    console.print(f"[bold green]✓ Found {len(programs)} Programs and {len(tokens)} Token Mints![/]\n")

    table = Table(title="Interacted Solana Programs")
    table.add_column("Program ID", style="cyan")
    table.add_column("Protocol / Name", style="green")
    table.add_column("Action", style="magenta")

    for prog in programs:
        name = KNOWN_PROGRAMS.get(prog, "Third-Party / Custom Program")
        success, path, meta = extractor.dump_program_binary(prog, output_dir)
        action_text = f"[green]Dumped .so binary[/]" if success else "[yellow]Logged account metadata[/]"
        table.add_row(prog, name, action_text)

    console.print(table)

    if tokens:
        t_table = Table(title="Interacted Token Mints (SPL Tokens)")
        t_table.add_column("Mint Address", style="cyan")
        for t in tokens:
            t_table.add_row(t)
        console.print(t_table)

    console.print(f"\n[bold green]📁 Solana artifacts saved to:[/] [underline]{os.path.abspath(output_dir)}/solana[/]")

def run_batch_analysis(results, output_dir):
    console.print("\n[bold magenta]🔬 Running Automated Static Analysis on Downloaded Contracts...[/]")
    analyzer = ContractAnalyzer()
    
    for addr, verified, path, meta in results:
        if not verified:
            continue
        src_dir = os.path.join(path, "src")
        target = src_dir if os.path.exists(src_dir) else path
        try:
            report = analyzer.run_slither(target, output_report_dir=path)
            md_out = os.path.join(path, "SECURITY_REPORT.md")
            analyzer.generate_markdown_report(report, md_out)
            summary = report.get("findings_summary", {})
            console.print(f"[cyan]{meta.get('contract_name')}[/] [{meta.get('category')}]: "
                          f"[red]High: {summary.get('High', 0)}[/] | "
                          f"[yellow]Med: {summary.get('Medium', 0)}[/] | "
                          f"[blue]Low: {summary.get('Low', 0)}[/]")
        except Exception as e:
            console.print(f"[dim]Failed to analyze {addr}: {e}[/]")

def generate_and_display_metrics(dataset_dir: str):
    console.print(f"\n[bold cyan]📊 Generating Dataset Metrics for Academic Paper from:[/] {dataset_dir}")
    generator = DatasetMetricsGenerator(dataset_dir=dataset_dir)
    metrics = generator.collect_dataset_data()

    json_file = os.path.join(dataset_dir, "DATASET_METRICS.json")
    md_file = os.path.join(dataset_dir, "DATASET_METRICS.md")

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    generator.generate_markdown_summary(metrics, md_file)

    # Print summary tables to terminal
    cat_table = Table(title="Dataset Category Breakdown")
    cat_table.add_column("Category", style="yellow")
    cat_table.add_column("Count", style="green", justify="right")
    cat_table.add_column("Percentage", style="cyan", justify="right")
    
    total = max(1, metrics["total_contracts"])
    for cat, count in sorted(metrics["categories"].items(), key=lambda x: x[1], reverse=True):
        cat_table.add_row(cat, str(count), f"{(count/total)*100:.1f}%")
    console.print(cat_table)

    vuln_table = Table(title="Vulnerability Cross-Tabulation by Category")
    vuln_table.add_column("Category", style="yellow")
    vuln_table.add_column("Contracts", style="white", justify="right")
    vuln_table.add_column("High", style="red", justify="right")
    vuln_table.add_column("Medium", style="yellow", justify="right")
    vuln_table.add_column("Low", style="blue", justify="right")
    vuln_table.add_column("Total Issues", style="magenta", justify="right")

    for cat, data in sorted(metrics["vulnerability_density_by_category"].items()):
        vuln_table.add_row(
            cat, str(data["total_contracts"]), str(data["High"]),
            str(data["Medium"]), str(data["Low"]), str(data["total_issues"])
        )
    console.print(vuln_table)

    console.print(f"\n[bold green]✓ Metrics JSON saved:[/] {json_file}")
    console.print(f"[bold green]✓ Metrics Markdown report saved:[/] {md_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Extract, classify, and analyze smart contracts from wallets across EVM and Solana for vulnerability research."
    )
    # Target Inputs
    parser.add_argument("--wallet", help="EVM wallet address (e.g. 0x5D06A812a8d5F301fDb4101E8F39eA73be39eEE4)")
    parser.add_argument("--contract", help="Single EVM contract address to download")
    parser.add_argument("--solana-wallet", help="Solana wallet address (e.g. 321v1oGkFAHnz89w2WL9YKj86PqHHtB48bvrap84sEMP)")
    parser.add_argument("--solana-program", help="Solana Program ID to dump binary for")
    
    # Options & Classification
    parser.add_argument("--chain", default="base", choices=list(EXPLORER_CONFIGS.keys()), help="EVM Chain (default: base)")
    parser.add_argument("--category", default="ALL", choices=[c.lower() for c in CATEGORIES_LIST] + CATEGORIES_LIST, help="Filter downloads by contract category (e.g. erc20_token, dex_router_aggregator, proxy_factory)")
    parser.add_argument("--output-dir", default="./contracts", help="Output directory for downloaded contracts")
    parser.add_argument("--api-key", default="", help="Block explorer API Key (optional, or set env var like BASESCAN_API_KEY)")
    parser.add_argument("--solana-rpc", default="https://api.mainnet-beta.solana.com", help="Solana RPC endpoint URL")
    parser.add_argument("--scan", help="Run static analysis on an existing downloaded contract folder")
    parser.add_argument("--auto-scan", action="store_true", help="Automatically run Slither analysis on downloaded contracts")
    parser.add_argument("--metrics", action="store_true", help="Compute and generate dataset categorization metrics and vulnerability breakdown")

    args = parser.parse_args()

    category_filter = args.category.upper()

    if args.metrics:
        generate_and_display_metrics(args.output_dir)
        return

    if args.scan:
        analyzer = ContractAnalyzer()
        console.print(f"[bold magenta]🔬 Running Slither on:[/] {args.scan}")
        report = analyzer.run_slither(args.scan)
        md_file = os.path.join(os.path.dirname(args.scan) if os.path.isfile(args.scan) else args.scan, "SECURITY_REPORT.md")
        analyzer.generate_markdown_report(report, md_file)
        console.print(f"[bold green]✓ Report generated:[/] {md_file}")
        return

    if args.wallet:
        process_evm_wallet(args.wallet, args.chain, args.output_dir, args.api_key, args.auto_scan, category_filter)
    elif args.contract:
        process_evm_contract(args.contract, args.chain, args.output_dir, args.api_key, args.auto_scan)
    elif args.solana_wallet:
        process_solana_wallet(args.solana_wallet, args.output_dir, args.solana_rpc)
    elif args.solana_program:
        extractor = SolanaExtractor(rpc_url=args.solana_rpc)
        success, path, meta = extractor.dump_program_binary(args.solana_program, args.output_dir)
        if success:
            console.print(f"[bold green]✓ Dumped program binary to:[/] {path}")
        else:
            console.print(f"[yellow]⚠️  Saved metadata to:[/] {path}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
