# Cryptanalysis of Side-Channel Vulnerabilities
## Timing Attack on RSA and Mitigation via Cryptographic Blinding

**Author:** Shayan  
**Course:** Cryptography  
**Instructor:** Muhammad Talha  

---

## Abstract
This paper investigates the threat of side-channel attacks, specifically timing attacks, on implementations of the RSA algorithm. Using PyCryptodome for industry-standard key generation, we implement a vulnerable "square-and-multiply" modular exponentiation and demonstrate how an attacker can deduce private key bits through statistical analysis of execution times. We then implement and evaluate RSA blinding as a countermeasure. Experimental results—including execution time, memory footprint, and throughput metrics—confirm that blinding successfully masks the timing variations dependent on the ciphertext.

## 1. Introduction
Cryptographic algorithms like RSA are mathematically secure under assumptions such as the hardness of factoring large integers. However, real-world implementations of these algorithms often leak information through physical channels—power consumption, electromagnetic emissions, or execution time. This project focuses on **timing attacks**, demonstrating how the varying execution time of RSA decryption can reveal the private key. We simulate an attack on a vulnerable RSA implementation and verify the effectiveness of RSA blinding as a constant-time countermeasure.

## 2. Literature Review
Side-channel attacks have been a critical area of cryptographic research since their formalization.

1. **Paul C. Kocher (1996) - "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems"** [IEEE]: This foundational paper introduced the concept of timing attacks, showing that attackers who can measure the time it takes a system to perform private key operations may be able to find the entire private key.

2. **David Brumley and Dan Boneh (2003) - "Remote Timing Attacks are Practical"** [USENIX Security / ACM]: This paper proved that timing attacks could be executed over a network against an OpenSSL-based web server, emphasizing the real-world danger of non-constant-time implementations.

## 3. Methodology & Implementation
We implemented a custom RSA system in Python using the **PyCryptodome** library for key generation (industry-standard). The vulnerability is intentionally introduced in the modular exponentiation routine to analyze the flaw, as permitted by the project guidelines.

### 3.1 Tools & Libraries Used
- **Language:** Python 3.x
- **Cryptographic Library:** PyCryptodome (for RSA key generation)
- **Metrics:** psutil (CPU), tracemalloc (Memory), time.perf_counter (Timing)
- **Visualization:** Streamlit, Matplotlib, NumPy

### 3.2 Vulnerable Implementation
The decryption process uses the standard "Square-and-Multiply" algorithm.
- For each bit of the private exponent `d`, a "square" operation is performed.
- If the bit is `1`, an additional "multiply" operation is performed.
Since the number of multiply operations strictly depends on the number of `1`s in the private key, the total execution time leaks information about the key.

### 3.3 Fixed Implementation (RSA Blinding)
To fix this, we implemented **RSA Blinding**, a technique that uncorrelates the decryption time from the input ciphertext.
1. Generate a random value `r` coprime to `n`.
2. Compute a blinded ciphertext: C' = C × r^e mod N.
3. Perform the vulnerable decryption on C' instead of C: M' = (C')^d mod N.
4. Unblind the result: M = M' × r^(-1) mod N.
Because C' is randomized, the attacker cannot correlate the timing variations to the original ciphertext C.

## 4. Experimental Evaluation
The attack simulation was conducted on a 1024-bit RSA key generated via PyCryptodome. A total of 100 random ciphertexts were generated and decrypted using both the vulnerable and the fixed (blinded) implementations. For each decryption, we measured execution time, CPU time, peak memory footprint, and throughput.

### 4.1 Metrics Measured
| Metric | Tool Used | Description |
|--------|-----------|-------------|
| Execution Time (ms) | `time.perf_counter` | Wall-clock time per decryption operation |
| CPU Time (ms) | `time.process_time` | Actual CPU cycles consumed, excluding I/O wait |
| Time Variance | NumPy `np.var()` | Statistical variance indicating timing consistency |
| Memory Footprint (KB) | `tracemalloc` | Peak memory allocated during decryption |
| Throughput (MB/s) | Computed | Data processed per second (key_size / time) |

### 4.2 Results Summary

| Metric | Vulnerable RSA | Fixed RSA (Blinding) |
|--------|---------------|----------------------|
| Avg Execution Time (ms) | 17.78 | 22.14 |
| Time Variance | 24.46 | 30.55 |
| Avg Memory Footprint (KB) | 2.25 | 2.83 |
| Avg Throughput (MB/s) | 0.01 | 0.01 |

### 4.3 Analysis of Results

**Execution Time:** The vulnerable implementation averaged 17.78 ms per decryption, while the blinded version averaged 22.14 ms — an overhead of approximately 24.5%. This overhead is caused by the additional blinding and unblinding modular exponentiations (computing r^e mod n and r^(-1) mod n). However, this cost is negligible for most practical applications.

**Time Variance:** The vulnerable RSA exhibited a variance of 24.46, indicating that execution times vary significantly depending on the Hamming weight (number of '1' bits) of the private key and the specific ciphertext input. The fixed implementation showed a variance of 30.55 — the higher variance here is expected because the blinding factor randomizes the computation, making timing *uncorrelated* with the original ciphertext even though absolute variance may increase.

**Memory Footprint:** The blinded implementation uses slightly more memory (2.83 KB vs 2.25 KB) due to the storage of the random blinding factor r, its modular inverse r^(-1), and the blinded ciphertext c'.

**Throughput:** Both implementations show comparable throughput (~0.01 MB/s), confirming that RSA blinding does not introduce a bottleneck for standard decryption workloads.

### 4.4 Graphical Results
The following figures illustrate the timing behavior of both implementations:

- **Figure 1 (timing_analysis.png):** Histogram showing the distribution of execution times. The vulnerable implementation shows a wider, right-skewed spread indicating data-dependent timing leakage. The fixed implementation shows a more uniform distribution.
- **Figure 2 (timing_comparison.png):** Scatter plot comparing per-sample execution times. The vulnerable RSA shows clear patterns correlated with ciphertext values, while the blinded version shows randomized scatter with no exploitable pattern.


## 5. Security Analysis & Threat Model
- **Threat Model**: The attacker is assumed to have access to the target system as a regular user or can interact with a decryption oracle that accepts chosen ciphertexts and returns the time taken.
- **Vulnerability**: The attacker exploits the deterministic and data-dependent execution time of the square-and-multiply algorithm. By submitting multiple ciphertexts and performing statistical analysis on the response times, the attacker can deduce individual bits of the private key.
- **Resilience**: RSA Blinding effectively neutralizes timing attacks by randomizing the input to the decryption function, making execution time independent of the original ciphertext.
- **Limitation of Countermeasure**: While RSA Blinding prevents timing attacks based on ciphertext manipulation, it does not protect against all cache-timing attacks if the multiplication operations themselves take variable time depending on the operand values. Further defenses would require strict constant-time arithmetic libraries.

## 6. Conclusion
This project practically demonstrates the severe threat posed by side-channel vulnerabilities. A mathematically secure algorithm can be broken trivially if its implementation is flawed. The implementation of RSA blinding proved to be a practical and effective countermeasure against standard timing attacks, highlighting the necessity of secure coding practices in cryptography.

## References
1. P. C. Kocher, "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems," in Advances in Cryptology — CRYPTO '96, Springer, 1996, pp. 104–113.
2. D. Brumley and D. Boneh, "Remote Timing Attacks are Practical," in Proceedings of the 12th USENIX Security Symposium, 2003.
