#!/usr/bin/env python3
import json
import requests
import hashlib
import argparse
from requests.auth import HTTPBasicAuth

##############################################################################
# 1) JSON-RPC Connector
##############################################################################
class BitcoinRPC:
    def __init__(self, user="bitcoin", password="bitcoin", host="127.0.0.1", port=8332):
        self.url = f"http://{host}:{port}"
        self.auth = HTTPBasicAuth(user, password)

    def call(self, method, params=None):
        if params is None:
            params = []
        headers = {'content-type': 'application/json'}
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': 0
        }
        response = requests.post(self.url, data=json.dumps(payload), headers=headers, auth=self.auth)
        response.raise_for_status()
        r = response.json()
        if r.get("error") is not None:
            raise Exception(f"RPC error: {r['error']}")
        return r['result']


##############################################################################
# 2) Block / Transaction Data Fetch
##############################################################################
def get_block_data(rpc, block_height):
    """
    Fetch block data (with full TX details, verbosity=2) from the given block height.
    """
    block_hash = rpc.call("getblockhash", [block_height])
    block_data = rpc.call("getblock", [block_hash, 2])
    return block_data


##############################################################################
# 3) Merkle & Hashing Helpers
##############################################################################
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def double_sha256(data: bytes) -> bytes:
    return sha256(sha256(data))

def calculate_merkle_root(transaction_hashes):
    """
    Compute merkle root for a list of transaction hashes (big-endian hex).
    """
    tx_hashes = [bytes.fromhex(txid)[::-1] for txid in transaction_hashes]
    while len(tx_hashes) > 1:
        new_level = []
        for i in range(0, len(tx_hashes), 2):
            left = tx_hashes[i]
            right = tx_hashes[i+1] if i+1 < len(tx_hashes) else tx_hashes[i]
            new_level.append(double_sha256(left + right))
        tx_hashes = new_level
    return tx_hashes[0][::-1].hex()

def build_merkle_tree(transaction_hashes):
    """
    Build and return the Merkle tree as a list of levels (each level is a list of LE bytes).
    """
    level = [bytes.fromhex(txid)[::-1] for txid in transaction_hashes]
    tree = [level]
    while len(level) > 1:
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else level[i]
            new_level.append(double_sha256(left + right))
        level = new_level
        tree.append(level)
    return tree

def get_merkle_branch(tree, index):
    """
    Extract the Merkle branch for the item at the given index (from the bottom level).
    Each sibling is kept as LE bytes.
    """
    branch = []
    for level in tree[:-1]:
        sibling_index = index ^ 1  # flip last bit
        if sibling_index < len(level):
            branch.append(level[sibling_index])
        index //= 2
    return branch

def format_merkle_branch(branch):
    """Format merkle branch from LE bytes to BE hex strings."""
    return [h.hex() for h in branch]

def verify_merkle_root(tx_hash_big_endian, merkle_branch_big_endian, expected_merkle_root, tx_index=0):
    """
    Verify the Merkle proof. Inputs are provided as big-endian hex (Stratum style).
    Returns (True/False, calculated_merkle_root).
    """
    current_hash = bytes.fromhex(tx_hash_big_endian)[::-1]  # convert to LE bytes

    for sibling_hex in merkle_branch_big_endian:
        # Convert sibling from BE hex to LE bytes
        sibling = bytes.fromhex(sibling_hex)
        if (tx_index % 2) == 0:
            combined = current_hash + sibling
        else:
            combined = sibling + current_hash
        current_hash = double_sha256(combined)
        tx_index //= 2

    calculated_root = current_hash[::-1].hex()  # back to BE hex
    return (calculated_root == expected_merkle_root, calculated_root)


##############################################################################
# 4) Searching for enonce2 in the Coinbase Transaction
##############################################################################
def find_enonce_fields_in_coinbase(coinbase_tx_hex):
    """
    Search coinbase TX hex for pattern:
      0x00 00 00 00 00 00 00 XX  (with XX != 0)
    Returns (enonce1, enonce2, enonce1_offset, enonce2_offset) or (None, None, None, None).
    """
    coinbase_bytes = bytes.fromhex(coinbase_tx_hex)
    needle = b"\x00" * 7
    for i in range(len(coinbase_bytes) - 7):
        if coinbase_bytes[i:i+7] == needle and coinbase_bytes[i+7] != 0:
            enonce2_offset = i
            enonce2 = coinbase_bytes[i:i+8]
            if enonce2_offset >= 4:
                enonce1_offset = enonce2_offset - 4
                enonce1 = coinbase_bytes[enonce1_offset:enonce1_offset+4]
                return (enonce1, enonce2, enonce1_offset, enonce2_offset)
    return (None, None, None, None)


##############################################################################
# 5) Stratum Helpers
##############################################################################
def reverse_hex_bytewise(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length must be even.")
    byte_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    return ''.join(byte_pairs[::-1])

def int_to_hex_le(value, length_bytes=4):
    """Convert an integer to little-endian hex representation."""
    return value.to_bytes(length_bytes, 'little').hex()

def int_to_hex_be(value, length_bytes=4):
    """Convert an integer to big-endian hex representation."""
    return value.to_bytes(length_bytes, 'big').hex()

def reverse_4byte_words(hash_hex_64):
    """
    Convert a 64-char hex string (32-byte hash) into Stratum's
    reversed-4-byte-word order.
    """
    if len(hash_hex_64) != 64:
        raise ValueError("Hash must be 64 hex chars.")
    words = [hash_hex_64[i:i+8] for i in range(0, 64, 8)]
    reversed_words = [w[6:8] + w[4:6] + w[2:4] + w[0:2] for w in words]
    return "".join(reversed_words)

def reverse_hex_bytewise(hex_string):
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length must be even.")
    # Split the string into pairs of two characters (bytes)
    byte_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
    # Reverse the order of the byte pairs
    reversed_pairs = byte_pairs[::-1]
    # Join them back into a single hex string
    return ''.join(reversed_pairs)

def to_stratum_hex(hex_string):
    return reverse_hex_bytewise(reverse_4byte_words(hex_string))

def from_stratum_hex(hex_string):
    return reverse_4byte_words(reverse_hex_bytewise(hex_string))


##############################################################################
# 6) Parse a SegWit Coinbase & Produce Legacy Serialization
##############################################################################
def read_varint(data, offset=0):
    """
    Minimal varint decode. Returns (value, new_offset).
    """
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        return int.from_bytes(data[offset+1:offset+3], 'little'), offset + 3
    elif first == 0xfe:
        return int.from_bytes(data[offset+1:offset+5], 'little'), offset + 5
    else:
        return int.from_bytes(data[offset+1:offset+9], 'little'), offset + 9

def encode_varint(i):
    """Minimal varint encoding."""
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def parse_coinbase_and_strip_witness(coinbase_hex):
    """
    Parse a coinbase transaction (which may include SegWit) and return its legacy serialization.
    Returns (nonwitness_bytes, full_tx_bytes).
    """
    tx_bytes = bytes.fromhex(coinbase_hex)
    cursor = 0

    # 1) version (4 bytes)
    version = tx_bytes[cursor:cursor+4]
    cursor += 4

    # 2) Check for segwit marker+flag
    marker = tx_bytes[cursor] if cursor < len(tx_bytes) else None
    flag = tx_bytes[cursor+1] if (cursor+1) < len(tx_bytes) else None
    is_segwit = (marker == 0 and flag == 1)
    if is_segwit:
        cursor += 2

    # 3) input count (varint)
    in_count, cursor = read_varint(tx_bytes, cursor)

    # 4) prev_out (36 bytes)
    vin = tx_bytes[cursor:cursor+36]
    cursor += 36

    # 5) scriptSig length (varint) and scriptSig
    script_len, cursor = read_varint(tx_bytes, cursor)
    script_sig = tx_bytes[cursor:cursor+script_len]
    cursor += script_len

    # 6) sequence (4 bytes)
    sequence = tx_bytes[cursor:cursor+4]
    cursor += 4

    # 7) output count (varint)
    out_count, cursor = read_varint(tx_bytes, cursor)

    # 8) outputs
    outputs_start = cursor
    for _ in range(out_count):
        cursor += 8  # value (8 bytes)
        pk_len, cursor = read_varint(tx_bytes, cursor)
        cursor += pk_len
    outputs = tx_bytes[outputs_start:cursor]

    # 9) If segwit, skip witness data
    if is_segwit:
        witness_count, cursor = read_varint(tx_bytes, cursor)
        for _ in range(witness_count):
            item_len, cursor = read_varint(tx_bytes, cursor)
            cursor += item_len

    # 10) locktime (4 bytes)
    locktime = tx_bytes[cursor:cursor+4]
    cursor += 4

    nonwitness_bytes = (version +
                        encode_varint(in_count) +
                        vin +
                        encode_varint(script_len) +
                        script_sig +
                        sequence +
                        encode_varint(out_count) +
                        outputs +
                        locktime)
    return nonwitness_bytes, tx_bytes


##############################################################################
# 7) Reconstruct Full Block Hash from Stratum Data
##############################################################################
def reconstruct_block_hash(
    coinb1_hex, enonce1_bytes, enonce2_hex, coinb2_hex,
    merkle_branch, prevhash_stratum, version_hex_be, ntime_hex_be, nbits_hex, nonce_hex_be
):
    """
    Reconstruct full block hash:
      1. Rebuild the coinbase transaction as: coinb1 + enonce1 + enonce2 + coinb2.
      2. Compute the legacy TXID (double-SHA of non-witness serialization).
      3. Rebuild the Merkle root (using the TXID and merkle branch).
      4. Assemble the block header and compute its double-SHA256.
    """
    coinb1_bytes = bytes.fromhex(coinb1_hex)
    coinb2_bytes = bytes.fromhex(coinb2_hex)
    enonce2_bytes = bytes.fromhex(enonce2_hex) if enonce2_hex else b""
    full_coinbase = coinb1_bytes + enonce1_bytes + enonce2_bytes + coinb2_bytes

    # Get legacy (non-witness) coinbase serialization and compute its TXID.
    nonwitness_bytes, _ = parse_coinbase_and_strip_witness(full_coinbase.hex())
    coinbase_txid_le = double_sha256(nonwitness_bytes)
    coinbase_txid_be_hex = coinbase_txid_le[::-1].hex()

    # Apply the Merkle branch (coinbase is at index 0, so we always hash as: current || sibling)
    current_hash = coinbase_txid_le
    for sibling_hex in merkle_branch:
        # Convert sibling from BE hex to LE bytes before concatenation.
        sibling_le = bytes.fromhex(sibling_hex)
        current_hash = double_sha256(current_hash + sibling_le)
    # Final merkle root in BE.
    merkle_root_be_hex = current_hash[::-1].hex()
    # For block header, keep merkle root in LE.
    merkle_root_le = current_hash

    # Use the previous block hash directly from node JSON.
    # (prevhash_stratum here is assumed to be the same as block_data["previousblockhash"])
    prevhash_le = bytes.fromhex(from_stratum_hex(prevhash_stratum))[::-1]

    # Process the version.
    # The mining.notify contained version already XORed with the mask,
    # so here we invert that XOR to obtain the original block version.
    version_le = bytes.fromhex(version_hex_be)[::-1]
    version_int = int.from_bytes(version_le, 'little') ^ 0x20000000
    version_le = version_int.to_bytes(4, 'little')

    ntime_le = bytes.fromhex(ntime_hex_be)[::-1]
    nonce_le = bytes.fromhex(nonce_hex_be)[::-1]
    bits_le = bytes.fromhex(nbits_hex)[::-1]

    block_header = (version_le +
                    prevhash_le +
                    merkle_root_le +
                    ntime_le +
                    bits_le +
                    nonce_le)
    block_hash_le = double_sha256(block_header)
    block_hash_be_hex = block_hash_le[::-1].hex()

    # Calculate difficulty for info.
    MAX_TARGET = 0xFFFF * (2 ** (8 * (0x1D - 3)))
    block_hash_num = int(block_hash_be_hex, 16)
    difficulty = MAX_TARGET / block_hash_num

    return {
        "coinbase_txid_be": coinbase_txid_be_hex,
        "merkle_root_be": merkle_root_be_hex,
        "block_hash_be": block_hash_be_hex,
        "difficulty": difficulty
    }

def reconstruct(notify, submit):
    """
    Shortcut for reconstructing the block hash from mining.notify and mining.submit parameters.
    """
    return reconstruct_block_hash(
        coinb1_hex=notify[2],
        enonce1_bytes=bytes([0x00, 0x00, 0x00, 0x00]),
        enonce2_hex=submit[2],
        coinb2_hex=notify[3],
        merkle_branch=notify[4],
        prevhash_stratum=notify[1],  # Now prevhash_stratum is simply the previous block hash as given by the node.
        version_hex_be=submit[5],
        ntime_hex_be=submit[3],
        nbits_hex=notify[6],
        nonce_hex_be=submit[4]
    )

##############################################################################
# 8) MAIN
##############################################################################
def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Scan blocks for nonce and version compatibility, and display mining pool information."
    )
    parser.add_argument(
        "-b", "--blockheight",
        type=int,
        default=878794,
        help="Starting block height for the scan (default: 878794)."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    block_height = args.blockheight

    #block_height = 878794  # Adjust as needed

    # Connect to local Bitcoin node.
    rpc = BitcoinRPC(user="bitcoin", password="bitcoin", host="127.0.0.1", port=8332)
    print(f"Fetching block at height {block_height} from local node...")
    block_data = get_block_data(rpc, block_height)
    print(f"Block Hash:    {block_data['hash']}")
    print(f"Block Version: {block_data['version']}")
    print(f"Block Time:    {block_data['time']}")
    print(f"Block Nonce:   {block_data['nonce']}\n")

    # Grab TXIDs and extract coinbase.
    txids = [tx["txid"] for tx in block_data["tx"]]
    coinbase_txid = txids[0]
    print(f"Coinbase TXID: {coinbase_txid}")

    coinbase_tx_data = block_data["tx"][0]
    if "hex" not in coinbase_tx_data:
        raise ValueError("No raw 'hex' for coinbase. Possibly pruned or missing TX index?")
    coinbase_hex_full = coinbase_tx_data["hex"]
    coinbase_nonwitness, _ = parse_coinbase_and_strip_witness(coinbase_hex_full)
    coinbase_hex = coinbase_nonwitness.hex()
    print(f"\nCoinbase TX hex:\n{coinbase_hex}\n")

    # Locate enonce fields.
    en1, en2, en1_offset, en2_offset = find_enonce_fields_in_coinbase(coinbase_hex)
    if en1 is None or en2 is None:
        raise Exception("Required enonce1 and enonce2 not found")
    if en1.hex() != "00000000" or en2.hex() != "00000000000000ff":
        raise Exception("enonce1 and enonce2 do not match expected values")
    print(f"enonce2 offset: {en2_offset}")
    print(f"enonce2 (8 bytes): {en2.hex()}")
    print(f"enonce1 offset: {en1_offset}")
    print(f"enonce1 (4 bytes): {en1.hex()}\n")

    # Verify Merkle Root.
    local_merkle_root = calculate_merkle_root(txids)
    block_merkle_root = block_data["merkleroot"]
    print(f"Calculated Merkle Root: {local_merkle_root}")
    print(f"Block's Merkle Root:    {block_merkle_root}")
    if local_merkle_root != block_merkle_root:
        raise Exception("Merkle root mismatch!")

    # Build Merkle tree and extract branch for coinbase.
    merkle_tree = build_merkle_tree(txids)
    coinbase_branch = get_merkle_branch(merkle_tree, 0)
    formatted_branch = format_merkle_branch(coinbase_branch)
    is_valid, recalculated_root = verify_merkle_root(
        tx_hash_big_endian=coinbase_txid,
        merkle_branch_big_endian=formatted_branch,
        expected_merkle_root=block_merkle_root,
        tx_index=0
    )
    print("\nMerkle Proof Verification:")
    print(f"Valid: {is_valid}")
    print(f"Recalculated root: {recalculated_root}")

    # Construct mining.notify parameters.
    job_id = "job123"
    # Instead of extra reversing, use the previous block hash directly.
    prevhash_stratum = to_stratum_hex(block_data["previousblockhash"])

    coinb1_hex = coinbase_hex[:en1_offset * 2]
    end_of_en2 = en2_offset + 8
    coinb2_hex = coinbase_hex[end_of_en2 * 2:]
    version_hex_be = int_to_hex_be(block_data["version"] ^ 0x20000000, 4)
    nbits_hex = block_data["bits"]
    ntime_hex_be = int_to_hex_be(block_data["time"], 4)
    clean_jobs = True

    mining_notify_params = [
        job_id,
        prevhash_stratum,
        coinb1_hex,
        coinb2_hex,
        formatted_branch,  # Merkle branch as BE hex strings.
        "20000000",
        nbits_hex,
        ntime_hex_be,
        clean_jobs
    ]
    mining_notify_message = {
        "id": None,
        "method": "mining.notify",
        "params": mining_notify_params
    }
    print("\nmining.notify message:")
    print(json.dumps(mining_notify_message, indent=2))

    # Construct mining.submit parameters.
    worker_name = "myMiner"
    extranonce2_hex = en2.hex() if en2 else "0000000000000000"
    block_nonce_be = block_data["nonce"].to_bytes(4, 'big').hex()
    mining_submit_params = [
        worker_name,
        job_id,
        extranonce2_hex,
        ntime_hex_be,
        block_nonce_be,
        version_hex_be
    ]
    mining_submit_message = {
        "id": 1,
        "method": "mining.submit",
        "params": mining_submit_params
    }
    print("\nmining.submit message:")
    print(json.dumps(mining_submit_message, indent=2))

    # Reconstruct final block hash.
    print("\nReconstructing final block hash...")
    results = reconstruct(mining_notify_params, mining_submit_params)
    print(f"Reconstructed Coinbase TXID (BE): {results['coinbase_txid_be']}")
    print(f"Reconstructed Merkle Root (BE):   {results['merkle_root_be']}")
    print(f"Reconstructed Block Hash (BE):    {results['block_hash_be']}")
    print(f"Actual Block Hash from Node:        {block_data['hash']}")

    if results["block_hash_be"] == block_data["hash"]:
        print("SUCCESS: Reconstructed block hash matches the actual block hash!")
    else:
        raise Exception("WARNING: Reconstructed block hash does NOT match actual block hash.")

    # Write the notify and submit messages to a file named "<block_height>.json".
    output = {'notify': mining_notify_message, 'submit': mining_submit_message}
    with open(f"{block_height}.json", "w") as f:
        json.dump(output, f, indent=2)

if __name__ == "__main__":
    main()
