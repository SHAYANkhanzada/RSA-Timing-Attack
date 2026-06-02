"""
Vulnerable RSA Implementation - Non-Constant Time Square-and-Multiply.

This module intentionally implements a FLAWED RSA decryption to demonstrate
how timing side-channels leak private key bits. This is the core of Track D analysis.

Note: We use PyCryptodome for key generation (industry-standard), but implement
the vulnerable modular exponentiation manually to analyze the flaw (as per guidelines).
"""

import time
from Crypto.PublicKey import RSA

class VulnerableRSA:
    def __init__(self, key_size=1024):
        """
        Generate RSA keys using PyCryptodome (industry-standard).
        The vulnerability is in the DECRYPTION routine, not the key generation.
        """
        self.key = RSA.generate(key_size)
        self.e = self.key.e
        self.d = self.key.d
        self.n = self.key.n
        self.key_size = key_size

    @classmethod
    def from_params(cls, e, d, n):
        """Create an instance from pre-existing key parameters (for testing)."""
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

    def decrypt_vulnerable(self, c):
        """
        VULNERABLE decryption using naive Square-and-Multiply.
        
        This is intentionally non-constant-time:
        - For each bit of private key 'd':
          - Always performs SQUARE (result = result^2 mod n)
          - Only performs MULTIPLY when bit is '1' (result = result * c mod n)
        
        The extra multiply operation for '1' bits causes measurable timing differences,
        leaking information about the private key bits.
        """
        result = 1
        d_binary = bin(self.d)[2:]

        for bit in d_binary:
            # Square step (always happens)
            result = (result * result) % self.n

            # Multiply step (only when bit is '1') - THIS IS THE VULNERABILITY
            if bit == '1':
                result = (result * c) % self.n

        return result

    def decrypt_secure(self, c):
        """
        Secure decryption using Python's built-in constant-time pow().
        This is what PyCryptodome uses internally.
        """
        return pow(c, self.d, self.n)


if __name__ == "__main__":
    print("=== Vulnerable RSA Demo (PyCryptodome key generation) ===")
    rsa = VulnerableRSA(key_size=1024)

    msg = 42
    print(f"Original Message: {msg}")

    ct = rsa.encrypt(msg)
    print(f"Ciphertext: {ct}")

    start = time.perf_counter()
    dt = rsa.decrypt_vulnerable(ct)
    end = time.perf_counter()

    print(f"Decrypted Message: {dt}")
    print(f"Vulnerable Decryption Time: {(end - start)*1000:.2f} ms")

    start = time.perf_counter()
    dt2 = rsa.decrypt_secure(ct)
    end = time.perf_counter()

    print(f"Secure Decryption Time: {(end - start)*1000:.2f} ms")
    print(f"Both produce same result: {dt == dt2}")
