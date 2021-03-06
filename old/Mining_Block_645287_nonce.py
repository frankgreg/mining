# http://engineering2finance.blogspot.com/2018/05/bitcoin-block-hashing-algorithm-part-iii.html

import hashlib
import binascii
import struct
import datetime
import time
import calendar

#####################################################
#####################################################
# DATA FROM https://btc.com/0000000000000000000ca006e5d26bb2ad04bfe5638af89dd8231c8208aa10e6

##################################################
#   ENTER DATA HERE
#################################################
# Block number
height           = 645287
d_version        = "2000e000"
d_previous_block = "0000000000000000000c56e88b2c1a3ff80199a835cdaff52a6b4771c00b35a1"
d_merkle_root    = "aaef8196de45ec9fd8656794d88d0fd5a7b91aefb59f74040d53e77db6febf12"
d_bits           = "171007ea"
d_nonce          = "354c87fa"
d = datetime.datetime(2020,8,25,8,55,52)
# d = datetime.datetime(year(4 digits),month,day,hour(24 hr),minutes,seconds)
#################################################
#################################################


# Block version number
ver = bytearray.fromhex(d_version)
ver.reverse()
version = ''.join(format(x, '02x') for x in ver)

# Previous block hash
pblk = bytearray.fromhex(d_previous_block)
pblk.reverse()
previous_blk = ''.join(format(x, '02x') for x in pblk)

# Merkle root
mkr = bytearray.fromhex(d_merkle_root)
mkr.reverse()
merkleroot = ''.join(format(x, '02x') for x in mkr)


# Bits
bt_0 = int(d_bits,16)
bt = hex(bt_0)[2:].zfill(8)
bthex = str(bt)
bts = bytearray.fromhex(bthex)
bts.reverse()
bits = ''.join(format(x, '02x') for x in bts)

# Time stamp
ts = time.mktime(d.timetuple())
tshex = hex(int(ts))[2:]
tsstr = str(tshex)
tstamp = bytearray.fromhex(tsstr)
tstamp.reverse()
timestamp = ''.join(format(x, '02x') for x in tstamp)

print("Block #                     = ", height)
print("Block version inverted 2x2  = ", version)
print("Previous block inverted 2x2 = ", previous_blk)
print("Merkle root inverted 2x2    = ", merkleroot)
print("Time stamp inverted 2x2     = ", timestamp)
print("Bits inverted 2x2           = ", bits)

# MINING

guess = int(d_nonce,16)
j = guess - 1000000
while j < int('ffffffff',16):

    n_0 = j
    n = hex(n_0)[2:].zfill(8)
    nhex = str(n)
    nn = bytearray.fromhex(nhex)
    nn.reverse()
    nonce = ''.join(format(x, '02x') for x in nn)

    header_hex = version + previous_blk + merkleroot + timestamp + bits + nonce
    header_bin = binascii.a2b_hex(header_hex)
    hash = hashlib.sha256(hashlib.sha256(header_bin).digest()).digest()
    hash_inv = binascii.b2a_hex(hash)
    hash_inv = str(hash_inv,'utf-8')
    hash = binascii.b2a_hex(hash[::-1])
    hash = str(hash,'utf-8')

    if int(hash,16) <= int('0000000000000000000fffffffffffffffffffffffffffffffffffffffffffff',16):
        nonce_r = hex(j)[2:].zfill(8)
        j = int('ffffffff',16)
    else:
        aaa = 20
    j = j + 1

print('')
print("Inverted hash:     ",hash_inv)
print("Block hash:        ",hash)
print("Nonce:             ",nonce_r)

nonce_decimal = int(nonce_r,16)
print("Nonce decimal:     ",nonce_decimal)