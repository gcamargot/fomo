import json
import os
from collections import defaultdict
from typing import Dict, List, Any

class DatasetMetricsGenerator:
    """
    Analyzes the downloaded contracts repository to compute distribution metrics,
    categorization statistics, and vulnerability cross-tabulations for academic papers.
    """

    def __init__(self, dataset_dir: str = "./contracts"):
        self.dataset_dir = os.path.abspath(dataset_dir)

    def collect_dataset_data(self) -> Dict[str, Any]:
        metrics = {
            "total_contracts": 0,
            "chains": defaultdict(int),
            "categories": defaultdict(int),
            "verification_status": {"verified": 0, "unverified_bytecode_only": 0},
            "proxy_distribution": {"proxy": 0, "direct": 0},
            "compilers": defaultdict(int),
            "solana_programs": 0,
            "vulnerability_density_by_category": defaultdict(lambda: {
                "total_contracts": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Informational": 0,
                "Optimization": 0,
                "total_issues": 0
            }),
            "contracts_index": []
        }

        if not os.path.exists(self.dataset_dir):
            return metrics

        # Traverse directory
        for root, dirs, files in os.walk(self.dataset_dir):
            if "metadata.json" in files:
                meta_path = os.path.join(root, "metadata.json")
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    continue

                metrics["total_contracts"] += 1
                chain = meta.get("chain", "unknown")
                metrics["chains"][chain] += 1

                # Solana handling
                if chain == "solana" or "program_id" in meta:
                    metrics["solana_programs"] += 1
                    category = "SOLANA_PROGRAM"
                    metrics["categories"][category] += 1
                    metrics["contracts_index"].append({
                        "id": meta.get("program_id", os.path.basename(root)),
                        "chain": "solana",
                        "category": category,
                        "verified": False,
                        "proxy": False
                    })
                    continue

                # EVM handling
                verified = meta.get("verified", False)
                if verified:
                    metrics["verification_status"]["verified"] += 1
                else:
                    metrics["verification_status"]["unverified_bytecode_only"] += 1

                is_proxy = meta.get("proxy", False)
                if is_proxy:
                    metrics["proxy_distribution"]["proxy"] += 1
                else:
                    metrics["proxy_distribution"]["direct"] += 1

                compiler = meta.get("compiler_version", "Unknown")
                # Simplify compiler version e.g. "0.8.20"
                if compiler and "+" in compiler:
                    compiler_short = compiler.split("+")[0]
                else:
                    compiler_short = compiler or "Unknown"
                metrics["compilers"][compiler_short] += 1

                category = meta.get("category", "CUSTOM_LOGIC")
                metrics["categories"][category] += 1
                metrics["vulnerability_density_by_category"][category]["total_contracts"] += 1

                # Check for security report in folder or src
                report_findings = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "Optimization": 0}
                slither_json = os.path.join(root, "slither_report.json")
                slither_src_json = os.path.join(root, "src", "slither_report.json")

                chosen_report = slither_json if os.path.exists(slither_json) else (slither_src_json if os.path.exists(slither_src_json) else None)
                if chosen_report:
                    try:
                        with open(chosen_report, "r", encoding="utf-8") as rf:
                            rep = json.load(rf)
                            for d in rep.get("results", {}).get("detectors", []):
                                imp = d.get("impact", "Informational")
                                if imp in report_findings:
                                    report_findings[imp] += 1
                                    metrics["vulnerability_density_by_category"][category][imp] += 1
                                    metrics["vulnerability_density_by_category"][category]["total_issues"] += 1
                    except Exception:
                        pass

                metrics["contracts_index"].append({
                    "address": meta.get("address", os.path.basename(root)),
                    "name": meta.get("contract_name", "Unknown"),
                    "chain": chain,
                    "category": category,
                    "verified": verified,
                    "proxy": is_proxy,
                    "compiler": compiler_short,
                    "findings": report_findings
                })

        return metrics

    def generate_markdown_summary(self, metrics: Dict[str, Any], output_path: str) -> str:
        md = []
        md.append("# Dataset Summary & Vulnerability Metrics for Academic Paper\n")
        md.append(f"**Total Analyzed Contracts / Programs:** `{metrics['total_contracts']}`  \n")
        md.append(f"**Verified Sources:** `{metrics['verification_status']['verified']}` | **Bytecode Only:** `{metrics['verification_status']['unverified_bytecode_only']}`\n\n")

        # Table 1: Category Distribution
        md.append("## 1. Smart Contract Categorization Breakdown\n")
        md.append("| Contract Category | Count | Percentage |")
        md.append("| :--- | :--- | :--- |")
        total = max(1, metrics["total_contracts"])
        for cat, count in sorted(metrics["categories"].items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            md.append(f"| **{cat}** | {count} | {pct:.1f}% |")
        md.append("\n---\n")

        # Table 2: Chain Distribution
        md.append("## 2. Blockchain Distribution\n")
        md.append("| Blockchain Network | Count | Percentage |")
        md.append("| :--- | :--- | :--- |")
        for ch, count in sorted(metrics["chains"].items(), key=lambda x: x[1], reverse=True):
            pct = (count / total) * 100
            md.append(f"| **{ch.upper()}** | {count} | {pct:.1f}% |")
        md.append("\n---\n")

        # Table 3: Vulnerability Cross-Tabulation by Category
        md.append("## 3. Vulnerability Cross-Tabulation by Category\n")
        md.append("| Category | Total Contracts | High | Medium | Low | Total Issues | Avg Issues/Contract |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for cat, data in sorted(metrics["vulnerability_density_by_category"].items()):
            n = max(1, data["total_contracts"])
            avg = data["total_issues"] / n
            md.append(f"| **{cat}** | {data['total_contracts']} | {data['High']} | {data['Medium']} | {data['Low']} | {data['total_issues']} | {avg:.2f} |")
        md.append("\n---\n")

        # Table 4: Compiler Versions
        md.append("## 4. Solidity Compiler Versions\n")
        md.append("| Compiler Version | Count |")
        md.append("| :--- | :--- |")
        for comp, count in sorted(metrics["compilers"].items(), key=lambda x: x[1], reverse=True):
            md.append(f"| `{comp}` | {count} |")
        md.append("\n")

        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        return content
