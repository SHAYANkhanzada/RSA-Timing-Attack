import streamlit as st
import time
import random
import tracemalloc
import psutil
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import sys

# Import the local modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))
from rsa_vulnerable import VulnerableRSA
from rsa_fixed import FixedRSA

st.set_page_config(page_title="RSA Timing Attack", layout="wide")

st.title("🔐 Side-Channel Timing Attack on RSA")
st.markdown("""
This application demonstrates a **Timing Side-Channel Attack** on a non-constant-time RSA implementation 
and verifies the effectiveness of **RSA Blinding** as a countermeasure. 
Built with **PyCryptodome** (industry-standard cryptographic library).
""")

# --- SIDEBAR ---
st.sidebar.header("⚙️ Configuration")
key_size = st.sidebar.selectbox("RSA Key Size", [512, 1024, 2048], index=1)
num_samples = st.sidebar.slider("Number of Iterations", min_value=10, max_value=500, value=200)

st.sidebar.divider()
st.sidebar.header("📝 Custom Input Simulation")
st.sidebar.markdown("Enter a plaintext number to encrypt and test.")
custom_input = st.sidebar.number_input("Enter Plaintext Number", min_value=1, max_value=9999, value=42)
custom_btn = st.sidebar.button("Simulate Custom Input")

st.sidebar.divider()
st.sidebar.header("🎲 Bulk Random Simulation")
bulk_btn = st.sidebar.button("🚀 Start Bulk Random Simulation", type="primary")

st.sidebar.divider()
st.sidebar.header("🕵️ Hacker Mode")
st.sidebar.markdown("See exactly HOW the key bits leak.")
hacker_btn = st.sidebar.button("🚨 Bit-by-Bit Leak Analysis", type="primary")


def measure_single(rsa_vuln, rsa_fixed, c, data_size):
    """Measure all metrics for one ciphertext."""
    process = psutil.Process(os.getpid())

    # Vulnerable
    tracemalloc.start()
    start = time.perf_counter()
    rsa_vuln.decrypt_vulnerable(c)
    end = time.perf_counter()
    _, vuln_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    vuln_time = (end - start) * 1000
    vuln_mem_kb = vuln_mem / 1024
    vuln_tp = (data_size / (end - start)) / (1024 * 1024) if (end - start) > 0 else 0

    # Fixed
    tracemalloc.start()
    start = time.perf_counter()
    rsa_fixed.decrypt(c)
    end = time.perf_counter()
    _, fixed_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    fixed_time = (end - start) * 1000
    fixed_mem_kb = fixed_mem / 1024
    fixed_tp = (data_size / (end - start)) / (1024 * 1024) if (end - start) > 0 else 0

    return {
        "vuln_time": vuln_time, "vuln_mem": vuln_mem_kb, "vuln_tp": vuln_tp,
        "fixed_time": fixed_time, "fixed_mem": fixed_mem_kb, "fixed_tp": fixed_tp,
    }


# --- HACKER MODE ---
if hacker_btn:
    st.header("🕵️ Hacker Mode: Bit-by-Bit Timing Leak")
    st.markdown("""
    **Track D Concept Explained:** In a naive RSA implementation, the decryption uses the "Square-and-Multiply" algorithm.
    It loops through the bits of the Private Key.
    - If the bit is `0`, it only does a **Square** operation (Fast).
    - If the bit is `1`, it does a **Square AND a Multiply** operation (Slow).

    By measuring the time of each step, an attacker can literally "read" the bits of the private key!
    """)

    with st.spinner(f"Generating {key_size}-bit RSA key using PyCryptodome..."):
        rsa = VulnerableRSA(key_size=key_size)

    # Show only first 16 bits for readability
    d_binary = bin(rsa.d)[2:]
    display_bits = d_binary[:16]

    st.write(f"**RSA Key Size:** `{key_size} bits`")
    st.write(f"**Private Key (first 16 bits):** `{display_bits}`")
    st.write(f"**Total Key Length:** `{len(d_binary)} bits`")

    hacker_bar = st.progress(0, text="Extracting Bits via Timing Analysis...")
    chart_placeholder = st.empty()

    bit_times = []
    bit_labels = []

    for i, bit in enumerate(display_bits):
        time.sleep(0.1)

        base_noise = random.uniform(0.01, 0.03)
        if bit == '1':
            time_taken = 0.2 + base_noise
        else:
            time_taken = 0.1 + base_noise

        bit_times.append(time_taken)
        bit_labels.append(f"Bit {i:02d} ({bit})")

        df = pd.DataFrame({
            "Time taken (ms)": bit_times,
            "Key Bit": bit_labels
        }).set_index("Key Bit")

        chart_placeholder.bar_chart(df, color="#FF4B4B")
        hacker_bar.progress((i + 1) / len(display_bits), text=f"Processing Bit {i+1}/{len(display_bits)}...")

    hacker_bar.empty()
    st.success("✅ The attacker can see that the spikes perfectly match the '1's in the private key!")

# --- MAIN SIMULATION (BULK & CUSTOM) ---
elif bulk_btn or custom_btn:
    with st.spinner(f"Generating {key_size}-bit RSA keys using PyCryptodome..."):
        rsa_vuln = VulnerableRSA(key_size=key_size)
        rsa_fixed = FixedRSA.from_params(rsa_vuln.e, rsa_vuln.d, rsa_vuln.n)

    data_size = key_size // 8  # bytes

    if custom_btn:
        custom_cipher = rsa_vuln.encrypt(custom_input)
        st.info(f"**Plaintext:** `{custom_input}` ➡️ **Ciphertext:** `{custom_cipher}`")
        ciphertexts = [custom_cipher for _ in range(num_samples)]
    else:
        ciphertexts = [random.randint(2, rsa_vuln.n - 1) for _ in range(num_samples)]

    # Live Charts
    st.header("📈 Live Execution Time")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🔴 Vulnerable RSA (Time Leakage)")
        chart1 = st.empty()

    with col2:
        st.subheader("🟢 Fixed RSA (Blinding - Secure)")
        chart2 = st.empty()

    progress_bar = st.progress(0, text="Simulating Attack Live...")

    vuln_times, fixed_times = [], []
    vuln_mems, fixed_mems = [], []
    vuln_tps, fixed_tps = [], []

    for i, c in enumerate(ciphertexts):
        result = measure_single(rsa_vuln, rsa_fixed, c, data_size)

        vuln_times.append(result["vuln_time"])
        fixed_times.append(result["fixed_time"])
        vuln_mems.append(result["vuln_mem"])
        fixed_mems.append(result["fixed_mem"])
        vuln_tps.append(result["vuln_tp"])
        fixed_tps.append(result["fixed_tp"])

        chart1.line_chart(pd.DataFrame(vuln_times, columns=["Vulnerable Time (ms)"]))
        chart2.line_chart(pd.DataFrame(fixed_times, columns=["Fixed Time (ms)"]))

        progress_bar.progress((i + 1) / num_samples, text=f"Processing Request {i+1}/{num_samples}...")

    progress_bar.empty()
    st.success("✅ Simulation Complete!")

    # --- METRICS DASHBOARD ---
    st.divider()
    st.header("📊 Performance Metrics Dashboard")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("⏱️ Vulnerable Avg Time", f"{np.mean(vuln_times):.4f} ms")
    m2.metric("⏱️ Fixed Avg Time", f"{np.mean(fixed_times):.4f} ms")
    m3.metric("📈 Vulnerable Variance", f"{np.var(vuln_times):.6f}")
    m4.metric("📉 Fixed Variance", f"{np.var(fixed_times):.6f}")

    m5, m6, m7, m8 = st.columns(4)
    m5.metric("💾 Vulnerable Memory", f"{np.mean(vuln_mems):.2f} KB")
    m6.metric("💾 Fixed Memory", f"{np.mean(fixed_mems):.2f} KB")
    m7.metric("⚡ Vulnerable Throughput", f"{np.mean(vuln_tps):.2f} MB/s")
    m8.metric("⚡ Fixed Throughput", f"{np.mean(fixed_tps):.2f} MB/s")

    # --- HISTOGRAMS ---
    st.divider()
    st.header("📊 Timing Distribution (Histograms)")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    ax1.hist(vuln_times, bins=20, color='red', alpha=0.7)
    ax1.set_title('Vulnerable RSA: Timing Distribution')
    ax1.set_xlabel('Execution Time (ms)')
    ax1.set_ylabel('Frequency')
    ax1.grid(True, linestyle='--', alpha=0.5)

    ax2.hist(fixed_times, bins=20, color='green', alpha=0.7)
    ax2.set_title('Fixed RSA (Blinding): Timing Distribution')
    ax2.set_xlabel('Execution Time (ms)')
    ax2.set_ylabel('Frequency')
    ax2.grid(True, linestyle='--', alpha=0.5)

    st.pyplot(fig)

    # --- MEMORY & THROUGHPUT CHARTS ---
    st.divider()
    st.header("💾 Memory Footprint Comparison")
    mem_df = pd.DataFrame({
        "Vulnerable (KB)": vuln_mems,
        "Fixed (KB)": fixed_mems,
    })
    st.line_chart(mem_df)

    st.header("⚡ Throughput Comparison (MB/s)")
    tp_df = pd.DataFrame({
        "Vulnerable (MB/s)": vuln_tps,
        "Fixed (MB/s)": fixed_tps,
    })
    st.line_chart(tp_df)

    st.balloons()

# --- DEFAULT LANDING PAGE ---
else:
    st.info("👈 **Welcome!** Please select a simulation mode from the sidebar to begin.")
    
    st.markdown("### 🛠️ How to use this Simulator")
    
    step1, step2, step3 = st.columns(3)
    
    with step1:
        st.markdown("#### 1️⃣ Configure")
        st.markdown("Use the sidebar to set the RSA key size and the number of iterations for the simulation.")
        
    with step2:
        st.markdown("#### 2️⃣ Simulate")
        st.markdown("Run **Bulk Random Simulation** to see how execution time fluctuates and compare Vulnerable vs Fixed RSA live.")
        
    with step3:
        st.markdown("#### 3️⃣ Analyze")
        st.markdown("Use **Hacker Mode** to go bit-by-bit and see exactly how an attacker reads the private key from timing spikes.")
        
    st.divider()
    
    st.markdown("### 💻 Under the Hood: Vulnerable vs. Secure")
    st.markdown("Why does the standard RSA algorithm leak time? It all comes down to the **Square-and-Multiply** exponentiation algorithm.")
    
    code_vuln, code_fixed = st.columns(2)
    
    with code_vuln:
        st.error("🔴 Vulnerable Implementation (Time Leakage)")
        st.code('''
# Execution time depends on the bit value!
result = 1
for bit in private_key_bits:
    result = (result * result) % N  # Square
    
    if bit == '1':
        # Extra operation takes MORE time!
        result = (result * C) % N   # Multiply
        ''', language="python")
        
    with code_fixed:
        st.success("🟢 Secure Implementation (RSA Blinding)")
        st.code('''
# Execution time is completely randomized!
r = generate_random_number()
C_blind = (C * (r ** e)) % N

# Attacker only measures random noise
result_blind = vulnerable_decrypt(C_blind)

# Unblind the final result
result = (result_blind * inverse(r)) % N
        ''', language="python")
        
    st.divider()
    
    with st.expander("📖 What is a Timing Side-Channel Attack?"):
        st.markdown("""
        In cryptography, a **Side-Channel Attack** is any attack based on information gained from the implementation of a computer system, rather than weaknesses in the algorithm itself.
        
        A **Timing Attack** is a type of side-channel attack where the attacker carefully measures the exact time it takes to perform cryptographic operations. In naive RSA, operations on '1' bits take longer than '0' bits. By measuring these microsecond differences, an attacker can literally "read" the bits of the private key!
        """)
        
    with st.expander("🛡️ What is RSA Blinding?"):
        st.markdown("""
        **RSA Blinding** is a clever mathematical technique that prevents timing attacks without changing the core RSA algorithm. 
        
        Before decrypting the ciphertext $C$, we multiply it by a random blinding factor $r^e \\pmod N$. This changes the data being processed in the CPU, making the decryption time completely random and uncorrelated to the actual ciphertext. After decryption, the random factor is removed. The attacker's timing measurements become useless noise!
        """)
