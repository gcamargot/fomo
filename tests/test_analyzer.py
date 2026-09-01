import os
import tempfile
from analyzer import ContractAnalyzer

def test_analyzer_generate_markdown_report():
    analyzer = ContractAnalyzer()
    analysis_result = {
        "target": "contracts/base/0xTest/src/Token.sol",
        "findings_summary": {
            "High": 1,
            "Medium": 2,
            "Low": 0,
            "Informational": 3,
            "Optimization": 0
        },
        "detectors": [
            {
                "check": "arbitrary-send-erc20",
                "impact": "High",
                "confidence": "High",
                "description": "Token transfers without checking return value."
            },
            {
                "check": "reentrancy-no-eth",
                "impact": "Medium",
                "confidence": "Medium",
                "description": "State variable updated after external call."
            }
        ]
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "SECURITY_REPORT.md")
        content = analyzer.generate_markdown_report(analysis_result, out_file)

        assert os.path.exists(out_file)
        assert "# Static Analysis Security Report" in content
        assert "arbitrary-send-erc20" in content
        assert "| **High** | 1 |" in content
        assert "| **Medium** | 2 |" in content
