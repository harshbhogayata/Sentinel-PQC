"""
Test Sample: Vulnerable Cryptographic Patterns
===============================================
This file contains intentional cryptographic vulnerabilities for testing
the Sentinel-PQC scanner. Each pattern is annotated with its expected
risk classification.

DO NOT USE THIS CODE IN PRODUCTION!
"""

# Standard imports - the scanner should detect these
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.PublicKey import DSA

# Alias import - scanner should still detect RSA usage
from Crypto.PublicKey import RSA as PyRSA


# =============================================================================
# RSA VULNERABILITIES
# =============================================================================

# CRITICAL: RSA-1024 is factorable with modern classical computers
weak_rsa_key = RSA.generate(1024)

# HIGH: RSA-2048 is secure classically but vulnerable to Shor's algorithm
standard_rsa_key = RSA.generate(2048)

# HIGH: Using keyword argument (scanner must handle this!)
rsa_with_kwargs = RSA.generate(bits=2048, e=65537)

# MEDIUM: RSA-4096 is still quantum-vulnerable but has larger margin
strong_rsa_key = RSA.generate(4096)

# Test with alias - should still be detected as RSA
aliased_rsa = PyRSA.generate(1024)

# Tricky case: exponent first as positional (shouldn't confuse scanner)
# Note: This is actually invalid syntax for pycryptodome, but tests robustness
# rsa_exponent_first = RSA.generate(65537, 2048)  # Commented - invalid


# =============================================================================
# AES PATTERNS
# =============================================================================

# MEDIUM: AES-128 has reduced security under Grover's attack (64-bit effective)
key_128 = b'Sixteen byte key'  # 16 bytes = 128 bits
aes_128 = AES.new(key_128, AES.MODE_GCM)

# LOW: AES-256 maintains 128-bit security post-quantum
key_256 = b'This is a 32 byte key for AES!!'  # 32 bytes = 256 bits
aes_256 = AES.new(key_256, AES.MODE_GCM)


# =============================================================================
# DSA PATTERNS
# =============================================================================

# CRITICAL: DSA-1024 is deprecated
weak_dsa = DSA.generate(1024)

# HIGH: DSA-2048 still vulnerable to Shor's algorithm
dsa_key = DSA.generate(bits=2048)


# =============================================================================
# ECC PATTERNS (for future detection)
# =============================================================================

# These would require additional imports and may be detected in Phase 2:
# from cryptography.hazmat.primitives.asymmetric import ec
# ecc_key = ec.generate_private_key(ec.SECP256R1())


# =============================================================================
# SAFE PATTERNS (for comparison - should NOT trigger alerts or be LOW risk)
# =============================================================================

# These are not crypto operations - shouldn't be flagged
import random
random_number = random.randint(1, 100)

# String that looks like crypto but isn't
rsa_description = "RSA is an asymmetric algorithm"


def generate_report():
    """Function name contains 'generate' but isn't crypto."""
    return {"status": "safe"}
