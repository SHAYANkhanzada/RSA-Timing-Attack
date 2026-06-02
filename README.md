# Side-Channel Vulnerabilities: RSA Timing Attack

This repository contains the implementation for **Track D (Cryptanalysis of Side-Channel Vulnerabilities)** for the Cryptography course project.

## Overview
This project demonstrates a **Timing Attack** on a naive (non-constant time) implementation of the RSA algorithm. It also implements and verifies **RSA Blinding** as a countermeasure. Built using **PyCryptodome** (industry-standard cryptographic library).

## Project Structure
```
PROJECT/
├── app.py                    # Streamlit Web GUI (main application)
├── src/
│   ├── rsa_vulnerable.py     # Vulnerable RSA (non-constant-time square-and-multiply)
│   ├── rsa_fixed.py          # Fixed RSA (RSA Blinding countermeasure)
│   ├── attack.py             # Timing attack simulation with full metrics
│   └── visualize.py          # Generates static graphs
├── Report.md                 # Research report (Markdown)
├── Report.docx               # Research report (Word)
├── Presentation.md           # 5-minute presentation summary
└── README.md                 # This file
```

## Libraries Used
- **PyCryptodome** - Industry-standard RSA key generation
- **psutil** - CPU usage measurement
- **tracemalloc** - Memory footprint tracking
- **Streamlit** - Web-based interactive GUI
- **Matplotlib / NumPy** - Graphs and statistical analysis

## Setup Instructions
1. Ensure you have Python 3.x installed.
2. Install required dependencies:
   ```bash
   pip install pycryptodome psutil streamlit matplotlib numpy
   ```

## How to Run

### Option 1: Web GUI (Recommended)
```bash
streamlit run app.py
```
This opens a web browser with:
- **Bulk Random Simulation** - Test with random ciphertexts
- **Custom Input Simulation** - Test your own plaintext
- **Hacker Mode** - Visualize bit-by-bit key leakage

### Option 2: Command Line
```bash
python src/attack.py
python src/visualize.py
```

## Metrics Measured
| Metric | Description |
|--------|-------------|
| Execution Time (ms) | Time per decryption operation |
| Time Variance | Timing consistency indicator |
| Memory Footprint (KB) | Peak memory during decryption |
| Throughput (MB/s) | Data processing speed |

## Screenshots

### Application Dashboard
![Dashboard 1](screenshots/DashBoard%201.jpeg)
![Dashboard 2](screenshots/DashBoard%202.jpeg)

### Live Execution Time Analysis
![Live Execution Time](screenshots/Live%20Execution%20Time.jpeg)

### Performance Metrics & Timing Distributions
![Performance Metrics](screenshots/Performance%20Metrics%20DashBoard.jpeg)
![Timing Distribution](screenshots/Timing%20Distribution%20(Histograms).jpeg)

### Memory Footprint & Throughput Comparison
![Memory & Throughput](screenshots/Memory%20Footprint%20and%20ThroughPut%20Comparison.jpeg)
