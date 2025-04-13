#!/usr/bin/env python3
import binascii
import sys
from bitcoin.rpc import RawProxy, JSONRPCError

# Set up connection to the Bitcoin Core node.
RPC_USER = "bitcoin"
RPC_PASSWORD = "bitcoin"
PROXY = RawProxy(service_url=f"http://{RPC_USER}:{RPC_PASSWORD}@127.0.0.1:8332")

# Masks for nonce and version checks.
# nerdqaxe+
#BIT_MASK = 0xffff0ffe  # Specified bit mask for the nonce.
#VERSION_MASK = 0x1fffe000  # Allowed version bits after considering 0x20000000.

# nerdqaxe++
BIT_MASK = 0xffff1ffe  # Specified bit mask for the nonce.
VERSION_MASK = 0x07ffe000  # Allowed version bits after considering 0x20000000.

# Known mining pool identifiers (mapping pool name to an identifying string).
POOL_IDENTIFIERS = {
    "AntPool": "AntPool",
    "F2Pool": "f2pool",
    "BTC.com": "BTC.COM",
    "ViaBTC": "ViaBTC",
    "SlushPool": "slush",
    "Binance Pool": "binance",
    "Foundry USA": "Foundry",
    # Add more known strings as needed.
}


def nonce_matches_mask(nonce: int, mask: int) -> bool:
    """
    Check if a nonce matches the bit mask.

    Returns True if all bits outside the mask are zero.
    """
    return nonce & ~mask == 0


def version_matches_mask(version: int, allowed_mask: int) -> bool:
    """
    Check if the version field, after XORing with 0x20000000, uses only the allowed bits.

    Returns True if all bits outside the allowed mask are zero.
    """
    mined_version = version ^ 0x20000000
    return mined_version & ~allowed_mask == 0


def get_mining_pool_info(block_hash: str) -> str:
    """
    Determine the mining pool for a block using its coinbase input script.

    If the node is pruned and the block data isn’t available, print a note and exit.
    Returns the pool name if found; otherwise, returns "Unknown Pool".
    """
    try:
        # Verbosity 2 includes full transaction details.
        block = PROXY.getblock(block_hash, 2)
    except JSONRPCError as e:
        err_msg = e.error.get("message", "")
        if "pruned" in err_msg.lower():
            print("Block not available (pruned data).")
            print("Your node is pruned and cannot provide full block data for this scan.")
            sys.exit(0)
        else:
            raise

    coinbase_tx = block['tx'][0]  # The first transaction is the coinbase.
    coinbase_input_script = coinbase_tx['vin'][0].get('coinbase', '')

    try:
        decoded = binascii.unhexlify(coinbase_input_script).decode('utf-8', errors='ignore')
    except Exception as ex:
        decoded = f"Unable to decode: {ex}"

    for pool_name, identifier in POOL_IDENTIFIERS.items():
        if identifier.lower() in decoded.lower():
            return pool_name

    return "Unknown Pool"


def scan_blocks():
    """
    Scan blocks from the latest to genesis. For each block, check if both the nonce and version
    fields match the provided masks. If a block qualifies, fetch and display its mining pool info.
    """
    latest_block_height = PROXY.getblockcount()
    print(f"Starting scan from block height: {latest_block_height}\n")

    for height in range(latest_block_height, 0, -1):
        block_hash = PROXY.getblockhash(height)
        block_header = PROXY.getblockheader(block_hash)
        nonce = block_header['nonce']
        version = block_header['version']

        if nonce_matches_mask(nonce, BIT_MASK) and version_matches_mask(version, VERSION_MASK):
            pool_info = get_mining_pool_info(block_hash)
            mined_version = version ^ 0x20000000
            print(f"Block {block_hash} (Height {height}) has matching nonce: {nonce:08x}")
            print(f"  Version: {version:08x} (Mined Version: {mined_version:08x})")
            print(f"  Mined by: {pool_info}\n")


if __name__ == "__main__":
    scan_blocks()
