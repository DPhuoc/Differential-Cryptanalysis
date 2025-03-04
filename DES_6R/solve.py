import os
from des import *
from tqdm import tqdm, trange
from pwn import xor
import itertools

key_real = os.urandom(8)
key_real = bytes_to_bits(key_real)

left_rotate_order = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
K6_cand = [{} for i in range(8)]

def attack_6_round_des(diff, sbox_index, attempts):
    for _ in trange(attempts):
        t1 = os.urandom(8)
        t2 = bytes([v ^ diff[i] for i, v in enumerate(t1)])

        t1 = bytes_to_bits(t1)
        t2 = bytes_to_bits(t2)

        ct1 = des(t1, key_real, 'e')
        ct2 = des(t2, key_real, 'e')

        ct1 = permute(ct1, INITIAL_PERMUTATION_TABLE)
        ct2 = permute(ct2, INITIAL_PERMUTATION_TABLE)

        lpt = [x ^ y for x, y in zip(ct1[:32], ct2[:32])]
        lpt[5] ^= 1
        lpt = permutate_rev(lpt, P_BOX_TABLE)

        d1 = permute(ct1[32:], EXPANSION_PERMUTATION_TABLE)
        d2 = permute(ct2[32:], EXPANSION_PERMUTATION_TABLE)

        for i in sbox_index:
            for ki in itertools.product(range(2), repeat=6):
                b1 = [x ^ y for x, y in zip(ki, d1[6 * i:6 * i + 6])]
                b2 = [x ^ y for x, y in zip(ki, d2[6 * i:6 * i + 6])]

                b1 = one_s_box(b1, S_BOX_TABLE[i])
                b2 = one_s_box(b2, S_BOX_TABLE[i])

                Dpi = [x ^ y for x, y in zip(b1, b2)]

                if Dpi == lpt[4 * i:4 * i + 4]:
                    if K6_cand[i].get(ki):
                        K6_cand[i][ki] += 1
                    else:
                        K6_cand[i][ki] = 1    

diff = bytes([0x40, 0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00])
diff = bytes_to_bits(diff)
diff = permute(diff, FINAL_PERMUTATION_TABLE)
diff = bits_to_bytes(diff)
attack_6_round_des(diff, [1, 4, 5, 6, 7], 512)

diff = bytes([0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x04, 0x00])
diff = bytes_to_bits(diff)
diff = permute(diff, FINAL_PERMUTATION_TABLE)
diff = bits_to_bytes(diff)
attack_6_round_des(diff, [0, 3], 512)

key = [sorted(K6_cand[i].items(), key=lambda item: item[1])[-1][0] if i != 2 else [] for i in range(8)]

for K4_1 in itertools.product(range(2), repeat=6):
    for K_remain in itertools.product(range(2), repeat=64 - len(KEY_PERMUTATION_TABLE)):
        K4 = []
        for i in range(8):
            if i == 2:
                K4 += list(K4_1)
            else:
                K4 += list(key[i])
        K4 += list(K_remain)
        lk, rk = split_block(permutate_rev(K4, COMPRESSION_PERMUTATION_TABLE + [8, 17, 21, 24, 34, 37, 42, 53]))

        for i in range(5, -1, -1):
            lk, rk = left_rotate([lk, rk], -left_rotate_order[i])


        key_ = lk + rk + [0] * 8
        key_ = permutate_rev(key_, KEY_PERMUTATION_TABLE + [7, 15, 23, 31, 39, 47, 55, 63])

        for i in range(100):
            pt = os.urandom(8)
            pt = bytes_to_bits(pt)
            
            ct1 = des(pt, key_real, 'e')
            ct2 = des(pt, key_, 'e')

            if ct1 != ct2:
                break
        else:
            print("FOUND")
            print(bits_to_bytes(key_real).hex())
            print(bits_to_bytes(key_).hex())