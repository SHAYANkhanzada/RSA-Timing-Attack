import matplotlib.pyplot as plt
import numpy as np
import os

def generate_graphs():
    if not os.path.exists('vuln_times.npy') or not os.path.exists('fixed_times.npy'):
        print("Data files not found. Please run attack.py first.")
        return

    vuln_times = np.load('vuln_times.npy')   # Already in ms from attack.py
    fixed_times = np.load('fixed_times.npy') # Already in ms from attack.py

    plt.figure(figsize=(12, 6))

    # Plot 1: Vulnerable RSA Timing Distribution
    plt.subplot(1, 2, 1)
    plt.hist(vuln_times, bins=20, color='red', alpha=0.7)
    plt.title('Vulnerable RSA: Timing Distribution')
    plt.xlabel('Execution Time (ms)')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.5)

    # Plot 2: Fixed RSA Timing Distribution
    plt.subplot(1, 2, 2)
    plt.hist(fixed_times, bins=20, color='green', alpha=0.7)
    plt.title('Fixed RSA (Blinding): Timing Distribution')
    plt.xlabel('Execution Time (ms)')
    plt.ylabel('Frequency')
    plt.grid(True, linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.savefig('timing_analysis.png', dpi=300)
    print("Graph saved as 'timing_analysis.png'")

    # Line Plot comparison
    plt.figure(figsize=(10, 5))
    plt.plot(vuln_times, label='Vulnerable RSA', color='red', marker='o', markersize=3, linestyle='None')
    plt.plot(fixed_times, label='Fixed RSA (Blinding)', color='green', marker='x', markersize=3, linestyle='None')
    plt.title('Execution Time per Sample')
    plt.xlabel('Sample Index')
    plt.ylabel('Execution Time (ms)')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.savefig('timing_comparison.png', dpi=300)
    print("Graph saved as 'timing_comparison.png'")

if __name__ == "__main__":
    generate_graphs()
