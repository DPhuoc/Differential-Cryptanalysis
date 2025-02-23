import os
from gf2bv import LinearSystem
from utils import des

def bytes_to_bits(byte_data):
    return [int(bit) for byte in byte_data for bit in format(byte, '08b')]

def bits_to_bytes(bits):
    byte_values = [int("".join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]
    return bytes(byte_values)

lin = LinearSystem([1] * (8 * 8))
key = lin.gens()

fs = []
key_real = os.urandom(8)
key_real = bytes_to_bits(key_real)

pt = os.urandom(8)
pt = bytes_to_bits(pt)

ct_symbolic = des(pt, key, 'e')

ct = des(pt, key_real, 'e')

for i in range(len(ct_symbolic)):
    fs.append(ct_symbolic[i] ^ int(ct[i]))

cnt = 0
for sol in lin.solve_all(fs):
    test = list(sol)
    assert des(pt, test, 'e') == des(pt, key_real, 'e')
    cnt += 1

print(cnt)