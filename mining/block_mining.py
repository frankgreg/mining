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
        print(f'Temps écoulé = {stop - start:.5f} s')

    return calculate_elapsed_time


@elapsed_time
def block_mining(block_data):
    version = convert_integer_to_reversed_hex(block_data['ver'])
    previous_block = convert_hex_to_reversed_hex(block_data['prev_block'])
    merkle_root = convert_hex_to_reversed_hex(block_data['mrkl_root'])
    timestamp = convert_datetime_to_reversed_hex(block_data['time'])
    bits = convert_integer_to_reversed_hex(block_data['bits'])
    target = calculate_target(block_data['bits'])
    block_nonce = block_data['nonce']

    nonce_guess = block_nonce - int(1e6)
    counter = 1
    while nonce_guess >= 0:
        nonce = convert_integer_to_reversed_hex(nonce_guess)
        header_hex = f'{version}{previous_block}{merkle_root}{timestamp}{bits}{nonce}'
        header_bin = binascii.a2b_hex(header_hex)
        hash_byte = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
        hash_int = int.from_bytes(hash_byte, byteorder='little')
        if hash_int <= target:
            reversed_hash_byte = hash_byte[::-1]
            hash_found = reversed_hash_byte.hex()
            print(
                f'Nonce officiel : {block_nonce}\n'
                f'Nonce trouvé:    {nonce_guess}\n'
                f'Nonce trouvé hex: {hex(nonce_guess)}\n'
                f'Hash officiel : {block_data["hash"]}\n'
                f'Hash trouvé :   {hash_found}\n'
                f"Nombre d'essais : {counter}"
            )
            break
        nonce_guess += 1
        counter += 1


def convert_datetime_to_reversed_hex(datetime_):
    timestamp = int(datetime_.timestamp())
    reversed_hex = convert_integer_to_reversed_hex(timestamp)

    return reversed_hex


def convert_integer_to_reversed_hex(integer):
    bytes_ = integer.to_bytes(4, byteorder='little')
    bytearray_ = bytearray(bytes_)
    reversed_hex = ''.join(format(byte, '02x') for byte in bytearray_)

    return reversed_hex


def convert_hex_to_reversed_hex(hex_):
    bytearray_ = bytearray.fromhex(hex_)
    reversed_bytearray = bytearray_[::-1]
    reversed_hex = ''.join(format(byte, '02x') for byte in reversed_bytearray)

    return reversed_hex


def calculate_target(bits):
    bits_hex = format(bits, 'x')
    index = int(bits_hex[:2], 16)
    coefficient = int(bits_hex[2:], 16)
    target = coefficient*2**(8*(index-3))

    return target


if __name__ == '__main__':
    # url = 'https://btc.com/00000000000000000006adad23e5d52bf49614e796f6dc694b13af2d7f05a32f'
    # url = 'https://btc.com/0000000000000000000ca006e5d26bb2ad04bfe5638af89dd8231c8208aa10e6'
    # url = 'https://btc.com/00000000000000000005e72210f6d25e0381fbe8e4b26888d22a58a5fb6b801c'
    url = 'https://btc.com/0000000000000000000796982f53f6fff215a7c23f4fb8f41ffe31772b731f23'
    BLOCK_HASH = url.split('/')[-1]
    main(BLOCK_HASH)
