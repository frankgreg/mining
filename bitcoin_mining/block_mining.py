import binascii
import hashlib
from datetime import datetime
import time
import requests
import pprint

'''
Source:
http://engineering2finance.blogspot.com/2018/05/bitcoin-block-hashing-algorithm-part-iii.html
'''

def main(block_hash):
    block_data = get_block_data_from_blockchain_api(block_hash)
    # block_data = get_block_data_from_btc_api(block_hash)
    block_mining(block_data)


def elapsed_time(function):
    def calculate_elapsed_time(*args, **kwargs):
        start = time.perf_counter()
        function(*args, **kwargs)
        stop = time.perf_counter()
        print(f'Temps écoulé = {stop - start} s')

    return calculate_elapsed_time


def get_block_data_from_blockchain_api(block_hash):
    url = f'https://blockchain.info/rawblock/{block_hash}'
    response = requests.get(url=url)
    block_data = response.json()

    return block_data


def get_block_data_from_btc_api(block_hash):
    url = f'https://chain.api.btc.com/v3/block/{block_hash}'
    response = requests.get(url=url)
    block_data = response.json()['data']
    pprint.pprint(block_data)

    return block_data


@elapsed_time
def block_mining(block_data):
    # btc api
    # version = convert_integer_to_reversed_hex(block_data['version'], 'x')
    # previous_block = convert_hex_to_reversed_hex(block_data['prev_block_hash'])
    # timestamp = convert_integer_to_reversed_hex(block_data['timestamp'], 'x')
    # merkle_root = convert_hex_to_reversed_hex(block_data['mrkl_root'])
    # bits = convert_integer_to_reversed_hex(block_data['bits'], 'x')
    # block_nonce = block_data['nonce']  # 3145652740

    # blockchain api
    version = convert_integer_to_reversed_hex(block_data['ver'], 'x')
    previous_block = convert_hex_to_reversed_hex(block_data['prev_block'])
    merkle_root = convert_hex_to_reversed_hex(block_data['mrkl_root'])
    timestamp = convert_integer_to_reversed_hex(block_data['time'], 'x')
    bits = convert_integer_to_reversed_hex(block_data['bits'], 'x')
    block_nonce = block_data['nonce']  # 3145652740

    guess = block_nonce - 1000
    # guess = 0
    while guess >= 0:
        nonce = convert_integer_to_reversed_hex(guess, '08x')

        header_hex = version + previous_block + merkle_root + timestamp + bits + nonce
        header_bin = binascii.a2b_hex(header_hex)

        hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
        hash_inv = binascii.b2a_hex(hash)
        hash_inv = str(hash_inv, 'utf-8')
        hash = binascii.b2a_hex(hash[::-1])
        hash = str(hash, 'utf-8')

        # https://blockchain.info/q/getdifficulty
        # hex(int(1.7345997805929E13))
        if int(hash, 16) <= int('0000000000000000000fffffffffffffffffffffffffffffffffffffffffffff', 16):
            print(f'Nonce integer: {guess}')
            nonce_found = hex(guess)
            print(f'Nonce hex: {nonce_found}')
            break
        guess += 1


def convert_integer_to_reversed_hex(integer, format_spec):
    hex_ = format(integer, format_spec)
    reversed_hex = convert_hex_to_reversed_hex(hex_)

    return reversed_hex


def convert_hex_to_reversed_hex(hex_):
    try:
        bytearray_ = bytearray.fromhex(hex_)
    except:
        a = 0
    reversed_bytearray = bytearray_[::-1]
    reversed_hex = ''.join(format(byte, '02x') for byte in reversed_bytearray)

    return reversed_hex


# print("Block #                     = ", height)
# print("Block version inverted 2x2  = ", version)
# print("Previous block inverted 2x2 = ", previous_blk)
# print("Merkle root inverted 2x2    = ", merkleroot)
# print("Time stamp inverted 2x2     = ", timestamp)
# print("Bits inverted 2x2           = ", bits)

# print('')
# print("Inverted hash:     ", hash_inv)
# print("Block hash:        ", hash)
# print("Nonce:             ", nonce_r)
# nonce_decimal = int(nonce_r, 16)
# print("Nonce decimal:     ", nonce_decimal)
# Nonce = 0xbb7eda04

if __name__ == '__main__':
    # https://btc.com/00000000000000000006adad23e5d52bf49614e796f6dc694b13af2d7f05a32f
    BLOCK_HASH = '00000000000000000006adad23e5d52bf49614e796f6dc694b13af2d7f05a32f'
    BLOCK_HEIGHT = 645180
    main(BLOCK_HASH)

    # https://btc.com/0000000000000000000ca006e5d26bb2ad04bfe5638af89dd8231c8208aa10e6
    # BLOCK_HEIGHT = 645287
    # main(BLOCK_HEIGHT)
