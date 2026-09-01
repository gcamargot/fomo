import json
import os
import subprocess
from typing import Dict, Optional

class ContractAnalyzer:
    def __init__(self, slither_path: str = "slither"):
        self.slither_path = slither_path

    def run_slither(self, target_path: str, output_report_dir: Optional[str] = None) -> Dict:
        """
        Runs Slither static analysis on a Solidity file or folder of source files,
        returning structured findings categorized by impact and confidence.
        """
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        json_out = os.path.join(output_report_dir or os.path.dirname(target_path), "slither_report.json")

        # Run slither command with JSON output
        cmd = [
            self.slither_path,
            target_path,
            "--json", json_out,
            "--solc-disable-warnings"
        ]

        # Allow execution even if slither finds issues (returns non-zero on findings)
        proc = subprocess.run(cmd, capture_output=True, text=True)

        results = {
            "target": target_path,
            "success": False,
            "raw_stdout": proc.stdout,
            "raw_stderr": proc.stderr,
            "findings_summary": {
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Informational": 0,
                "Optimization": 0,
            },
            "detectors": []
        }

        if os.path.exists(json_out):
            try:
                with open(json_out, "r", encoding="utf-8") as f:
                    data = json.load(f)

                results["success"] = data.get("success", False)
                detectors = data.get("results", {}).get("detectors", [])

                for d in detectors:
                    impact = d.get("impact", "Informational")
                    confidence = d.get("confidence", "Unknown")
                    check = d.get("check", "")
                    description = d.get("description", "").strip()

                    if impact in results["findings_summary"]:
                        results["findings_summary"][impact] += 1
                    else:
                        results["findings_summary"][impact] = 1

                    results["detectors"].append({
                        "check": check,
                        "impact": impact,
                        "confidence": confidence,
                        "description": description,
                        "first_markdown_element": d.get("first_markdown_element", ""),
                    })

            except Exception as e:
                results["parse_error"] = str(e)

        return results

    def generate_markdown_report(self, analysis_result: Dict, output_md_file: str) -> str:
        """
        Generates an academic / audit-ready Markdown summary of the analysis findings.
        """
        target = analysis_result.get("target", "Unknown")
        summary = analysis_result.get("findings_summary", {})
        detectors = analysis_result.get("detectors", [])

        md = []
        md.append("# Static Analysis Security Report\n")
        md.append(f"**Target:** `{target}`  \n")
        md.append(f"**Total Findings:** {len(detectors)}  \n\n")

        md.append("## Vulnerability Breakdown\n")
        md.append("| Impact | Count |")
        md.append("| :--- | :--- |")
        for impact in ["High", "Medium", "Low", "Informational", "Optimization"]:
            count = summary.get(impact, 0)
            md.append(f"| **{impact}** | {count} |")
        md.append("\n---\n")

        md.append("## Detailed Findings\n")
        if not detectors:
            md.append("_No automated detector findings triggered._\n")
        else:
            for idx, d in enumerate(detectors, 1):
                md.append(f"### {idx}. [{d['impact']}] {d['check']} (Confidence: {d['confidence']})\n")
                md.append(f"**Description:**\n```\n{d['description']}\n```\n")

        report_content = "\n".join(md)
        with open(output_md_file, "w", encoding="utf-8") as f:
            f.write(report_content)

        return report_content
