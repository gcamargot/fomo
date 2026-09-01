import json
import os
import tempfile
from dataset_metrics import DatasetMetricsGenerator

def test_dataset_metrics_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        generator = DatasetMetricsGenerator(dataset_dir=tmpdir)
        metrics = generator.collect_dataset_data()
        assert metrics["total_contracts"] == 0
        assert metrics["solana_programs"] == 0

def test_dataset_metrics_with_evm_and_solana_contracts():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create EVM contract metadata
        evm_dir = os.path.join(tmpdir, "base", "0x1234567890abcdef")
        os.makedirs(evm_dir, exist_ok=True)
        with open(os.path.join(evm_dir, "metadata.json"), "w") as f:
            json.dump({
                "chain": "base",
                "verified": True,
                "proxy": False,
                "compiler_version": "v0.8.20+commit.a1b2c3d4",
                "category": "ERC20_TOKEN",
                "contract_name": "TestToken"
            }, f)

        # Create Solana program metadata
        solana_dir = os.path.join(tmpdir, "solana", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
        os.makedirs(solana_dir, exist_ok=True)
        with open(os.path.join(solana_dir, "metadata.json"), "w") as f:
            json.dump({
                "chain": "solana",
                "program_id": "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
            }, f)

        generator = DatasetMetricsGenerator(dataset_dir=tmpdir)
        metrics = generator.collect_dataset_data()

        assert metrics["total_contracts"] == 2
        assert metrics["solana_programs"] == 1
        assert metrics["chains"]["base"] == 1
        assert metrics["chains"]["solana"] == 1
        assert metrics["verification_status"]["verified"] == 1
        assert metrics["categories"]["ERC20_TOKEN"] == 1
        assert metrics["categories"]["SOLANA_PROGRAM"] == 1

        # Test Markdown report generation
        md_path = os.path.join(tmpdir, "DATASET_METRICS.md")
        md_content = generator.generate_markdown_summary(metrics, md_path)
        assert os.path.exists(md_path)
        assert "Total Analyzed Contracts / Programs:" in md_content
        assert "ERC20_TOKEN" in md_content
