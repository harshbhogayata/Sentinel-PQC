# 🛡️ Sentinel-PQC Remediation Plan

> Generated: 2026-01-20 00:14:44
> Standard: NIST SP 800-208 (Post-Quantum Cryptography)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| 🔴 CRITICAL Vulnerabilities | 3 |
| 🟡 HIGH Vulnerabilities | 3 |
| **Total Requiring Remediation** | **6** |

---

## Detailed Remediation Steps

### 🔴 Vulnerability 1: RSA-1024 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 25)
**Risk Level:** CRITICAL
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  20    # =============================================================================
  21    # RSA VULNERABILITIES
  22    # =============================================================================
  23    
  24    # CRITICAL: RSA-1024 is factorable with modern classical computers
  25 >> weak_rsa_key = RSA.generate(1024)
  26    
  27    # HIGH: RSA-2048 is secure classically but vulnerable to Shor's algorithm
  28    standard_rsa_key = RSA.generate(2048)
  29    
  30    # HIGH: Using keyword argument (scanner must handle this!)
```

**Sentinel Suggested Fix:**
```python
RSA.generate(4096)
```

**Rationale:** RSA-1024 is cryptographically weak. Upgrade to 4096 bits for crypto-agility.

**Reference:** NIST SP 800-131A Rev.2

---

### 🔴 Vulnerability 2: RSA-1024 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 37)
**Risk Level:** CRITICAL
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  32    
  33    # MEDIUM: RSA-4096 is still quantum-vulnerable but has larger margin
  34    strong_rsa_key = RSA.generate(4096)
  35    
  36    # Test with alias - should still be detected as RSA
  37 >> aliased_rsa = PyRSA.generate(1024)
  38    
  39    # Tricky case: exponent first as positional (shouldn't confuse scanner)
  40    # Note: This is actually invalid syntax for pycryptodome, but tests robustness
  41    # rsa_exponent_first = RSA.generate(65537, 2048)  # Commented - invalid
  42    
```

**Sentinel Suggested Fix:**
```python
RSA.generate(4096)
```

**Rationale:** RSA-1024 is cryptographically weak. Upgrade to 4096 bits for crypto-agility.

**Reference:** NIST SP 800-131A Rev.2

---

### 🔴 Vulnerability 3: DSA-1024 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 62)
**Risk Level:** CRITICAL
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  57    # =============================================================================
  58    # DSA PATTERNS
  59    # =============================================================================
  60    
  61    # CRITICAL: DSA-1024 is deprecated
  62 >> weak_dsa = DSA.generate(1024)
  63    
  64    # HIGH: DSA-2048 still vulnerable to Shor's algorithm
  65    dsa_key = DSA.generate(bits=2048)
  66    
  67    
```

**Sentinel Suggested Fix:**
```python
# CRITICAL: Migrate to Ed25519 or ML-DSA
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# key = Ed25519PrivateKey.generate()
```

**Rationale:** DSA-1024 is deprecated. Migrate to Edwards curves or ML-DSA (Dilithium).

**Reference:** FIPS 186-5

---

### 🟡 Vulnerability 4: RSA-2048 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 28)
**Risk Level:** HIGH
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  23    
  24    # CRITICAL: RSA-1024 is factorable with modern classical computers
  25    weak_rsa_key = RSA.generate(1024)
  26    
  27    # HIGH: RSA-2048 is secure classically but vulnerable to Shor's algorithm
  28 >> standard_rsa_key = RSA.generate(2048)
  29    
  30    # HIGH: Using keyword argument (scanner must handle this!)
  31    rsa_with_kwargs = RSA.generate(bits=2048, e=65537)
  32    
  33    # MEDIUM: RSA-4096 is still quantum-vulnerable but has larger margin
```

**Sentinel Suggested Fix:**
```python
RSA.generate(4096)
```

**Rationale:** RSA-2048 is quantum-vulnerable. Upgrade to 4096 bits as interim measure.

**Reference:** CNSA 2.0 (2025 deadline)

---

### 🟡 Vulnerability 5: RSA-2048 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 31)
**Risk Level:** HIGH
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  26    
  27    # HIGH: RSA-2048 is secure classically but vulnerable to Shor's algorithm
  28    standard_rsa_key = RSA.generate(2048)
  29    
  30    # HIGH: Using keyword argument (scanner must handle this!)
  31 >> rsa_with_kwargs = RSA.generate(bits=2048, e=65537)
  32    
  33    # MEDIUM: RSA-4096 is still quantum-vulnerable but has larger margin
  34    strong_rsa_key = RSA.generate(4096)
  35    
  36    # Test with alias - should still be detected as RSA
```

**Sentinel Suggested Fix:**
```python
RSA.generate(4096)
```

**Rationale:** RSA-2048 is quantum-vulnerable. Upgrade to 4096 bits as interim measure.

**Reference:** CNSA 2.0 (2025 deadline)

---

### 🟡 Vulnerability 6: DSA-2048 in `vulnerable.py`

**Location:** `test_samples\vulnerable.py` (Line 65)
**Risk Level:** HIGH
**Fix Source:** RULE_ENGINE (HIGH)

**Original Code:**
```python
  60    
  61    # CRITICAL: DSA-1024 is deprecated
  62    weak_dsa = DSA.generate(1024)
  63    
  64    # HIGH: DSA-2048 still vulnerable to Shor's algorithm
  65 >> dsa_key = DSA.generate(bits=2048)
  66    
  67    
  68    # =============================================================================
  69    # ECC PATTERNS (for future detection)
  70    # =============================================================================
```

**Sentinel Suggested Fix:**
```python
# WARNING: Plan migration to ML-DSA (Dilithium)
# DSA is quantum-vulnerable regardless of key size
```

**Rationale:** DSA is vulnerable to Shor's algorithm. Plan PQC migration.

**Reference:** NIST PQC Standards

---

## 🚀 Post-Quantum Migration Roadmap

| Current Algorithm | PQC Replacement | Timeline |
|-------------------|-----------------|----------|
| RSA (Key Exchange) | ML-KEM (Kyber-768/1024) | 2025-2030 |
| RSA/DSA (Signatures) | ML-DSA (Dilithium) | 2025-2030 |
| ECDSA/ECDH | Hybrid (ECC + ML-KEM) | 2024-2025 |
| AES-128 | AES-256 (Grover's mitigation) | Immediate |

> **Source:** NIST CNSA 2.0 Suite, NIST SP 800-208

---

*Generated by Sentinel-PQC Remediator v1.0*