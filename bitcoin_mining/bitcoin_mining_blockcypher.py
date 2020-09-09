import binascii
import hashlib
import time

from blockcypher import get_block_overview

'''
Source:
http://engineering2finance.blogspot.com/2018/05/bitcoin-block-hashing-algorithm-part-iii.html
'''


def main(block_hash):
    block_data = get_block_overview(block_hash)
    block_mining(block_data)


def elapsed_time(function):
    def calculate_elapsed_time(*args, **kwargs):
        start = time.perf_counter()
        function(*args, **kwargs)
        stop = time.perf_counter()
        print(f'Temps écoulé = {stop - start} s')

    return calculate_elapsed_time


@elapsed_time
def block_mining(block_data):
    version = convert_integer_to_reversed_hex(block_data['ver'], 'x')
    previous_block = convert_hex_to_reversed_hex(block_data['prev_block'])
    merkle_root = convert_hex_to_reversed_hex(block_data['mrkl_root'])
    timestamp = convert_datetime_to_reversed_hex(block_data['time'], 'x')
    bits = convert_integer_to_reversed_hex(block_data['bits'], 'x')
    block_nonce = block_data['nonce']
    difficulty = '0000000000000000000fffffffffffffffffffffffffffffffffffffffffffff'

    nonce_guess = block_nonce - 10000
    counter = 1
    while nonce_guess >= 0:
        nonce = convert_integer_to_reversed_hex(nonce_guess, '08x')
        header_hex = version + previous_block + merkle_root + timestamp + bits + nonce
        header_bin = binascii.a2b_hex(header_hex)
        hash_byte = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
        reversed_hash_byte = hash_byte[::-1]
        hash_hex = reversed_hash_byte.hex()
        if int(hash_hex, 16) <= int(difficulty, 16):
            print(
                f'Nonce officiel : {block_nonce}\n'
                f'Nonce trouvé: {nonce_guess}\n'
                f'Nonce trouvé hex: {hex(nonce_guess)}\n'
                f"Nombre d'essais : {counter}"
            )
            break
        nonce_guess += 1
        counter += 1


def convert_datetime_to_reversed_hex(datetime_, format_spec):
    timestamp = int(datetime_.timestamp())
    reversed_hex = convert_integer_to_reversed_hex(timestamp, format_spec)

    return reversed_hex


def convert_integer_to_reversed_hex(integer, format_spec):
    hex_ = format(integer, format_spec)
    reversed_hex = convert_hex_to_reversed_hex(hex_)

    return reversed_hex


def convert_hex_to_reversed_hex(hex_):
    bytearray_ = bytearray.fromhex(hex_)
    reversed_bytearray = bytearray_[::-1]
    reversed_hex = ''.join(format(byte, '02x') for byte in reversed_bytearray)

    return reversed_hex


if __name__ == '__main__':
    url = 'https://btc.com/00000000000000000006adad23e5d52bf49614e796f6dc694b13af2d7f05a32f'
    # url = 'https://btc.com/0000000000000000000ca006e5d26bb2ad04bfe5638af89dd8231c8208aa10e6'
    BLOCK_HASH = url.split('/')[-1]
    main(BLOCK_HASH)