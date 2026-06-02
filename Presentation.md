# Cryptanalysis of Side-Channel Vulnerabilities
## (5-Minute Presentation Summary)

### Slide 1: Introduction
- **Topic**: Timing Attack on RSA and its Countermeasure.
- **Problem Statement**: Algorithms like RSA are mathematically secure, but poor implementations can leak the private key through Side Channels (execution time).
- **Goal**: Demonstrate how timing variations occur and implement a countermeasure to fix it.

### Slide 2: Hypothesis & Threat Model
- **Hypothesis**: The execution time of a standard "Square-and-Multiply" RSA algorithm is directly correlated with the bits of the private key.
- **Threat Model**: If an attacker can measure the time taken to decrypt various ciphertexts, they can perform statistical analysis to uncover the private key.

### Slide 3: The Experiment (Vulnerable RSA)
- **Implementation**: Created a non-constant-time Python implementation of RSA.
- **Observation**: 
  - Exponentiation involves looping through the bits of the private key.
  - Bits set to '1' trigger an extra multiplication step.
  - More '1's = Longer execution time.
- **Result**: High variance in execution times across different ciphertexts.

### Slide 4: The Fix (RSA Blinding)
- **Countermeasure**: RSA Blinding.
- **How it Works**: 
  - Before decryption, the ciphertext is multiplied by a random blinding factor.
  - Decryption happens on this "blinded" text.
  - The result is then "unblinded".
- **Why it Works**: The time taken now depends on the random factor, completely breaking the correlation between the ciphertext and the execution time.

### Slide 5: Findings & Conclusion
- **Data Analysis**: 
  - *Show the Histograms (timing_analysis.png)*
  - Before Blinding: Broad timing distribution (leakage).
  - After Blinding: Uniform, tight timing distribution (secure).
- **Conclusion**: Security is only as strong as its weakest link. Implementing robust, constant-time algorithms or blinding techniques is essential for deploying secure cryptographic systems.
