class RC5:
    def __init__(self, key, w, r):
        self.w = w
        self.r = r
        self._expand_key(key, self.w, self.r)

    def _rotate_left(self, val, r_bits, max_bits):
        v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
        v2 = ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))
        return v1 | v2

    def _rotate_right(self, val, r_bits, max_bits):
        v1 = ((val & (2 ** max_bits - 1)) >> r_bits % max_bits)
        v2 = (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))

        return v1 | v2

    def _expand_key(self, key, wordsize, rounds):
        def _align_key(key, align_val):
            while len(key) % (align_val):
                key += b'\x00'

            L = []
            for i in range(0, len(key), align_val):
                L.append(int.from_bytes(key[i:i + align_val], byteorder='little'))

            return L

        def _const(w):
            if w == 16:
                return (0xB7E1, 0x9E37)
            elif w == 32:
                return (0xB7E15163, 0x9E3779B9)
            elif w == 64:
                return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
            
        def _extend_key(w, r):
            P, Q = _const(w)
            S = [P]
            t = 2 * (r + 1)
            for i in range(1, t):
                S.append((S[i - 1] + Q) % 2 ** w)

            return S

        def _mix(L, S, r, w, c):
            t = 2 * (r + 1)
            m = max(c, t)
            A = B = i = j = 0

            for k in range(3 * m):
                A = S[i] = self._rotate_left(S[i] + A + B, 3, w)
                B = L[j] = self._rotate_left(L[j] + A + B, A + B, w)

                i = (i + 1) % t
                j = (j + 1) % c

            return S
        
        aligned = _align_key(key, wordsize // 8)
        extended = _extend_key(wordsize, rounds)

        self.S = _mix(aligned, extended, rounds, wordsize, len(aligned))

    def rc5_encrypt(self, plaintext):
        mask = (2 ** self.w - 1)
        A, B = plaintext
        A = (A + self.S[0]) & mask
        B = (B + self.S[1]) & mask

        for i in range(1, self.r + 1):
            A = self._rotate_left(A ^ B, 8, self.w) + self.S[2 * i] & mask
            B = self._rotate_left(B ^ A, 8, self.w) + self.S[2 * i + 1] & mask

        return A, B


    def rc5_decrypt(self, ciphertext):
        mask = (2 ** self.w - 1)
        A, B = ciphertext

        for i in range(self.r, 0, -1):
            B = (B - self.S[2 * i + 1]) & mask
            B = self._rotate_right(B ^ A, 8, self.w)
            A = (A - self.S[2 * i]) & mask
            A = self._rotate_right(A ^ B, 8, self.w)

        B = (B - self.S[1]) & mask
        A = (A - self.S[0]) & mask

        return A, B
