from solana_extractor import SolanaExtractor, KNOWN_PROGRAMS

def test_solana_known_programs():
    assert "11111111111111111111111111111111" in KNOWN_PROGRAMS
    assert KNOWN_PROGRAMS["11111111111111111111111111111111"] == "System Program"
    assert "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" in KNOWN_PROGRAMS
    assert "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P" in KNOWN_PROGRAMS
    assert KNOWN_PROGRAMS["6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"] == "Pump.fun Bonding Curve"

def test_solana_extractor_init():
    extractor = SolanaExtractor()
    assert extractor.rpc_url == "https://api.mainnet-beta.solana.com"
