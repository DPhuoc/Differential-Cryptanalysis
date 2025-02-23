from RC5 import RC5
from Crypto.Util.number import *
import os
import random

key = os.urandom(16)

cipher = RC5(key, 32, 8)

with open('../wordlist.txt', 'rb') as f:
    plaintexts = f.read().split(b'\n')

plaintext = random.choice(plaintexts)

plaintext = (bytes_to_long(plaintext[:4]), bytes_to_long(plaintext[4:]))

ctA, ctB = cipher.rc5_encrypt(plaintext)

ptA = ptB = 0
brute = [(0, 0), (0, 1), (1, 0), (1, 1)]
for i in range(32):
    for k in brute:
        ptA ^= k[0] * 2 ** i
        ptB ^= k[1] * 2 ** i
        ctAt, ctBt = cipher.rc5_encrypt((ptA, ptB))
        if ctAt & (2 ** (i + 1) - 1) == ctA & (2 ** (i + 1) - 1) and ctBt & (2 ** (i + 1) - 1)== ctB & (2 ** (i + 1) - 1):
            break

        ptA ^= k[0] * 2 ** i
        ptB ^= k[1] * 2 ** i

print(long_to_bytes(ptA) + long_to_bytes(ptB))