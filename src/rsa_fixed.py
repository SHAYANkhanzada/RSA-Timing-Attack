"""
Fixed RSA Implementation - RSA Blinding Countermeasure.

This module implements RSA Blinding to prevent timing side-channel attacks.
Even if the underlying modular exponentiation is non-constant-time,
the blinding randomizes the input so that timing cannot be correlated
to the original ciphertext.

Uses PyCryptodome for key generation (industry-standard).
"""

import time
import random
import math
from Crypto.PublicKey import RSA

class FixedRSA:
    def __init__(self, key_size=1024):
        """
        Generate RSA keys using PyCryptodome (industry-standard).
        """
        self.key = RSA.generate(key_size)
        self.e = self.key.e
        self.d = self.key.d
        self.n = self.key.n
        self.key_size = key_size

    @classmethod
    def from_params(cls, e, d, n):
        """Create an instance from pre-existing key parameters."""
        instance = object.__new__(cls)
        instance.e = e
        instance.d = d
        instance.n = n
        instance.key_size = n.bit_length()
        instance.key = None
        return instance

    def encrypt(self, m):
        """Standard RSA encryption: c = m^e mod n"""
        return pow(m, self.e, self.n)

    def _vulnerable_modular_exponentiation(self, base, exp, mod):
        """
        Same vulnerable Square-and-Multiply as in rsa_vulnerable.py.
        Used here to show that RSA Blinding protects even a flawed implementation.
        """
        result = 1
        exp_binary = bin(exp)[2:]

        for bit in exp_binary:
            result = (result * result) % mod
            if bit == '1':
                result = (result * base) % mod

        return result

    def decrypt(self, c):
        """
        Fixed decryption using RSA Blinding countermeasure.

        Steps:
        1. Generate a random blinding factor 'r' coprime to n
        2. Compute blinded ciphertext: c' = c * r^e mod n
        3. Decrypt the BLINDED ciphertext (attacker sees random timing)
        4. Unblind the result: m = m' * r^-1 mod n

        Because c' is randomized, the attacker CANNOT correlate
        timing variations to the original ciphertext c.
        """
        # Step 1: Generate random blinding factor
        while True:
            r = random.randint(2, self.n - 1)
            if math.gcd(r, self.n) == 1:
                break

        # Step 2: Blind the ciphertext
        r_e = pow(r, self.e, self.n)
        c_prime = (c * r_e) % self.n

        # Step 3: Decrypt blinded ciphertext (timing now depends on random c')
        m_prime = self._vulnerable_modular_exponentiation(c_prime, self.d, self.n)

        # Step 4: Unblind the result
        r_inv = pow(r, -1, self.n)
        m = (m_prime * r_inv) % self.n

        return m


if __name__ == "__main__":
    print("=== Fixed RSA Demo (RSA Blinding + PyCryptodome) ===")
    rsa = FixedRSA(key_size=1024)

    msg = 42
    print(f"Original Message: {msg}")

    ct = rsa.encrypt(msg)
    print(f"Ciphertext: {ct}")

    start = time.perf_counter()
    dt = rsa.decrypt(ct)
    end = time.perf_counter()

    print(f"Decrypted Message: {dt}")
    print(f"Blinded Decryption Time: {(end - start)*1000:.2f} ms")
