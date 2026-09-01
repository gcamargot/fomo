import pytest
from evm_extractor import EVMExtractor, EXPLORER_CONFIGS

def test_explorer_configs():
    assert "base" in EXPLORER_CONFIGS
    assert "ethereum" in EXPLORER_CONFIGS
    assert "arbitrum" in EXPLORER_CONFIGS
    assert EXPLORER_CONFIGS["base"]["chain_id"] == 8453
    assert EXPLORER_CONFIGS["ethereum"]["chain_id"] == 1
    assert EXPLORER_CONFIGS["arbitrum"]["chain_id"] == 42161

def test_evm_extractor_init():
    extractor = EVMExtractor(chain="base")
    assert extractor.chain == "base"
    assert extractor.config["chain_id"] == 8453
    assert extractor.config["blockscout_v2"] == "https://base.blockscout.com/api/v2"

def test_evm_extractor_invalid_chain():
    with pytest.raises(ValueError):
        EVMExtractor(chain="invalid_chain_name")
