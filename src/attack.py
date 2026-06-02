"""
Timing Attack Simulation with Full Metrics.

Measures:
  - Execution Time (ms)
  - CPU Usage (%)
  - Memory Footprint (KB)
  - Throughput (MB/s)

Uses PyCryptodome-based RSA implementations from rsa_vulnerable.py and rsa_fixed.py.
"""

import time
import random
import tracemalloc
import psutil
import numpy as np
import os

from rsa_vulnerable import VulnerableRSA
from rsa_fixed import FixedRSA


def measure_execution(rsa_vuln, rsa_fixed, ciphertext, data_size_bytes):
    """
    Measures all 4 metrics for a single ciphertext decryption.
    Returns dict with vulnerable and fixed results.
    """
    process = psutil.Process(os.getpid())

    # --- Vulnerable ---
    tracemalloc.start()
    cpu_before = process.cpu_percent(interval=None)
    start = time.perf_counter()

    rsa_vuln.decrypt_vulnerable(ciphertext)

    end = time.perf_counter()
    cpu_after = process.cpu_percent(interval=None)
    _, vuln_mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    vuln_time = (end - start) * 1000  # ms
    vuln_cpu = cpu_after
    vuln_mem = vuln_mem_peak / 1024  # KB
    vuln_throughput = (data_size_bytes / (end - start)) / (1024 * 1024) if (end - start) > 0 else 0  # MB/s

    # --- Fixed (Blinding) ---
    tracemalloc.start()
    cpu_before = process.cpu_percent(interval=None)
    start = time.perf_counter()

    rsa_fixed.decrypt(ciphertext)

    end = time.perf_counter()
    cpu_after = process.cpu_percent(interval=None)
    _, fixed_mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    fixed_time = (end - start) * 1000  # ms
    fixed_cpu = cpu_after
    fixed_mem = fixed_mem_peak / 1024  # KB
    fixed_throughput = (data_size_bytes / (end - start)) / (1024 * 1024) if (end - start) > 0 else 0  # MB/s

    return {
        "vuln_time": vuln_time, "vuln_cpu": vuln_cpu,
        "vuln_mem": vuln_mem, "vuln_throughput": vuln_throughput,
        "fixed_time": fixed_time, "fixed_cpu": fixed_cpu,
        "fixed_mem": fixed_mem, "fixed_throughput": fixed_throughput,
    }


def simulate_attack():
    print("=" * 60)
    print("  Side-Channel Timing Attack Simulation (Full Metrics)")
    print("=" * 60)

    key_size = 1024
    print(f"\n[*] Generating {key_size}-bit RSA keys using PyCryptodome...")

    rsa_vuln = VulnerableRSA(key_size=key_size)
    rsa_fixed = FixedRSA.from_params(rsa_vuln.e, rsa_vuln.d, rsa_vuln.n)

    num_samples = 100
    data_size_bytes = key_size // 8  # 128 bytes for 1024-bit key

    ciphertexts = [random.randint(2, rsa_vuln.n - 1) for _ in range(num_samples)]

    # Collect metrics
    vuln_times, fixed_times = [], []
    vuln_mems, fixed_mems = [], []
    vuln_throughputs, fixed_throughputs = [], []

    print(f"[*] Running {num_samples} decryptions on each implementation...\n")

    for i, c in enumerate(ciphertexts):
        result = measure_execution(rsa_vuln, rsa_fixed, c, data_size_bytes)
        vuln_times.append(result["vuln_time"])
        fixed_times.append(result["fixed_time"])
        vuln_mems.append(result["vuln_mem"])
        fixed_mems.append(result["fixed_mem"])
        vuln_throughputs.append(result["vuln_throughput"])
        fixed_throughputs.append(result["fixed_throughput"])

        if (i + 1) % 25 == 0:
            print(f"  [{i+1}/{num_samples}] completed...")

    # Print Results
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)

    print(f"\n{'Metric':<25} {'Vulnerable RSA':<20} {'Fixed RSA (Blinding)':<20}")
    print("-" * 65)
    print(f"{'Avg Time (ms)':<25} {np.mean(vuln_times):<20.4f} {np.mean(fixed_times):<20.4f}")
    print(f"{'Time Variance':<25} {np.var(vuln_times):<20.6f} {np.var(fixed_times):<20.6f}")
    print(f"{'Avg Memory (KB)':<25} {np.mean(vuln_mems):<20.2f} {np.mean(fixed_mems):<20.2f}")
    print(f"{'Avg Throughput (MB/s)':<25} {np.mean(vuln_throughputs):<20.2f} {np.mean(fixed_throughputs):<20.2f}")

    # Save data for visualization
    np.save('vuln_times.npy', vuln_times)
    np.save('fixed_times.npy', fixed_times)
    np.save('vuln_mems.npy', vuln_mems)
    np.save('fixed_mems.npy', fixed_mems)
    np.save('vuln_throughputs.npy', vuln_throughputs)
    np.save('fixed_throughputs.npy', fixed_throughputs)
    print("\n[+] All timing data saved for visualization.")


if __name__ == "__main__":
    simulate_attack()
