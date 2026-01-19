# Sentinel-PQC 🛡️

**Post-Quantum Cryptography Orchestration Platform**

A comprehensive toolkit for detecting, simulating, and remediating cryptographic vulnerabilities in the post-quantum era.

![Dashboard](dashboard/public/screenshot.png)

---

![Sentinel PQC Dashboard](assets/dashboard_preview.png)

## 📋 Overview

Sentinel-PQC addresses the "Ghost Incompatibility" problem where large Post-Quantum Cryptography (PQC) keys cause network fragmentation. It provides:

1. **Static Analysis Scanner** - Detect cryptographic patterns in Python code
2. **PQC Network Proxy** - Simulate Kyber-768 handshakes and detect MTU fragmentation
3. **Compliance Dashboard** - Visualize risks with real-time Ghost alerts
4. **AI Remediator** - Generate NIST-compliant remediation plans

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SENTINEL-PQC                            │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  Module A   │  Module B   │  Module C   │    Module I      │
│   Scanner   │    Proxy    │  Dashboard  │   Remediator     │
│  (Python)   │    (Go)     │   (React)   │    (Python)      │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ Tree-Sitter │   CIRCL     │ Vite+React  │  Rule Engine     │
│    AST      │  Kyber-768  │  Recharts   │   + LLM API      │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ cbom.json   │ ghost.json  │    PDF      │ REMEDIATION.md   │
└─────────────┴─────────────┴─────────────┴──────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Go 1.21+
- Node.js 18+

### 1. Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/sentinel-pqc.git
cd sentinel-pqc

# Python dependencies
pip install -r requirements.txt

# Dashboard dependencies
cd dashboard && npm install && cd ..

# Go dependencies
cd proxy && go mod tidy && cd ..
```

### 2. Run the Scanner (Module A)

```bash
python main.py test_samples/vulnerable.py
```

**Output:** `cbom_output.json` - Cryptographic Bill of Materials

### 3. Run the Ghost Proxy (Module B)

```bash
# Terminal 1: Start the proxy
cd proxy && go run proxy.go

# Terminal 2: Simulate a PQC handshake
cd proxy && go run client.go
```

**Output:** `ghost_report.json` - MTU Fragmentation Report

### 4. Run the Dashboard (Module C)

```bash
cd dashboard
npm run dev
# Open http://localhost:5173
```

**Features:**
- 🔴 Pulsing Ghost Alert for fragmentation risk
- 📊 Donut chart showing risk distribution
- 📋 Audit table with all findings
- 📄 PDF Evidence Pack export

### 5. Generate Remediation Plan (Module I)

```bash
python remediator.py
```

**Output:** `REMEDIATION_PLAN.md` - NIST-compliant fix suggestions

---

## 📁 Project Structure

```
sentinel-pqc/
├── scanner.py           # Module A: AST-based crypto scanner
├── main.py              # CLI entry point for scanner
├── remediator.py        # Module I: AI-powered fix generator
├── requirements.txt     # Python dependencies
├── cbom_output.json     # Scanner output (generated)
├── REMEDIATION_PLAN.md  # Remediator output (generated)
│
├── proxy/               # Module B: Go PQC Proxy
│   ├── proxy.go         # TCP server with Kyber-768
│   ├── client.go        # Test client simulator
│   ├── go.mod           # Go dependencies
│   └── ghost_report.json # Proxy output (generated)
│
├── dashboard/           # Module C: React Dashboard
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   │       ├── GhostMonitor.jsx
│   │       ├── RiskChart.jsx
│   │       └── AuditTable.jsx
│   └── public/data/     # Data files for dashboard
│
└── test_samples/        # Sample vulnerable code
    └── vulnerable.py
```

---

## 🔬 Technical Details

### Scanner (Module A)
- **Technology:** Python + Tree-Sitter
- **Patterns Detected:** RSA, DSA, AES, DES, 3DES
- **Features:**
  - Keyword argument handling (`RSA.generate(bits=2048)`)
  - Import alias tracking (`from Crypto.PublicKey import RSA as PyRSA`)
  - NIST-based risk classification

### Proxy (Module B)
- **Technology:** Go + Cloudflare CIRCL
- **Algorithm:** ML-KEM-768 (Kyber-768)
- **Detection:** Flags handshakes > 1400 bytes (MTU limit)

### Dashboard (Module C)
- **Technology:** Vite + React + Tailwind CSS + Recharts
- **Features:**
  - Real-time Ghost fragmentation alerts
  - PDF export with jsPDF + FileSaver.js
  - Premium dark theme with glassmorphism

### Remediator (Module I)
- **Technology:** Python + Rule Engine
- **Features:**
  - Context window extraction (5 lines before/after)
  - Standard fix dictionary (NIST references)
  - LLM integration skeleton for AI fixes

---

## 📊 Risk Classification

| Risk Level | Criteria | Example |
|------------|----------|---------|
| 🔴 CRITICAL | Immediately breakable | RSA-1024, DES |
| 🟡 HIGH | Quantum-vulnerable | RSA-2048, DSA-2048 |
| 🔵 MEDIUM | Reduced margin (Grover) | AES-128 |
| 🟢 LOW | Quantum-resistant | AES-256 |

---

## 📚 References

- [NIST SP 800-208](https://csrc.nist.gov/publications/detail/sp/800-208/final) - PQC Recommendations
- [CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) - NSA Commercial Algorithm Suite
- [Cloudflare CIRCL](https://github.com/cloudflare/circl) - Go Cryptographic Library

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

**Built with 💻 by the Sentinel-PQC Team**
