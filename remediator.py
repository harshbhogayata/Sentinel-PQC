"""
Sentinel-PQC Remediator - Module I
===================================
AI-powered code remediation engine for cryptographic vulnerabilities.

This module:
1. Ingests findings from cbom_output.json
2. Extracts context windows from source files
3. Suggests fixes using rule-based engine + LLM skeleton
4. Generates a REMEDIATION_PLAN.md report

Usage:
    python remediator.py
    python remediator.py --cbom path/to/cbom.json --output FIXES.md
"""

import json
import os
import argparse
from datetime import datetime
from pathlib import Path


# =============================================================================
# CONFIGURATION
# =============================================================================

# Context window size (lines before and after vulnerable line)
CONTEXT_LINES = 5

# Risk levels to remediate (in priority order)
PRIORITY_RISKS = ["CRITICAL", "HIGH"]


# =============================================================================
# STANDARD FIX DICTIONARY
# =============================================================================
# Rule-based fixes for common vulnerabilities

STANDARD_FIXES = {
    # RSA Key Size Upgrades
    ("RSA", "generate", 1024): {
        "fix": "RSA.generate(4096)",
        "reason": "RSA-1024 is cryptographically weak. Upgrade to 4096 bits for crypto-agility.",
        "nist_ref": "NIST SP 800-131A Rev.2"
    },
    ("RSA", "generate", 2048): {
        "fix": "RSA.generate(4096)",
        "reason": "RSA-2048 is quantum-vulnerable. Upgrade to 4096 bits as interim measure.",
        "nist_ref": "CNSA 2.0 (2025 deadline)"
    },
    
    # DSA Upgrades
    ("DSA", "generate", 1024): {
        "fix": "# CRITICAL: Migrate to Ed25519 or ML-DSA\n# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n# key = Ed25519PrivateKey.generate()",
        "reason": "DSA-1024 is deprecated. Migrate to Edwards curves or ML-DSA (Dilithium).",
        "nist_ref": "FIPS 186-5"
    },
    ("DSA", "generate", 2048): {
        "fix": "# WARNING: Plan migration to ML-DSA (Dilithium)\n# DSA is quantum-vulnerable regardless of key size",
        "reason": "DSA is vulnerable to Shor's algorithm. Plan PQC migration.",
        "nist_ref": "NIST PQC Standards"
    },
    
    # AES Mode Upgrades
    ("AES", "new", None): {
        "fix": "AES.new(key, AES.MODE_GCM, nonce=nonce)",
        "reason": "Ensure authenticated encryption. Use GCM mode for integrity protection.",
        "nist_ref": "NIST SP 800-38D"
    },
    
    # DES Removal
    ("DES", "new", None): {
        "fix": "# CRITICAL: Replace DES with AES-256-GCM\nfrom Crypto.Cipher import AES\ncipher = AES.new(key_256, AES.MODE_GCM)",
        "reason": "DES is completely broken. Replace with AES-256 immediately.",
        "nist_ref": "NIST SP 800-131A"
    },
    ("DES3", "new", None): {
        "fix": "# CRITICAL: Replace 3DES with AES-256-GCM\nfrom Crypto.Cipher import AES\ncipher = AES.new(key_256, AES.MODE_GCM)",
        "reason": "3DES is deprecated. Replace with AES-256.",
        "nist_ref": "NIST SP 800-131A"
    },
}

# PQC Migration Recommendations
PQC_MIGRATIONS = {
    "RSA": "ML-KEM (Kyber) for key exchange, ML-DSA (Dilithium) for signatures",
    "DSA": "ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)",
    "ECDSA": "ML-DSA (Dilithium) for signatures",
    "ECDH": "ML-KEM (Kyber) for key exchange",
    "DH": "ML-KEM (Kyber) for key exchange",
}


# =============================================================================
# CONTEXT EXTRACTION
# =============================================================================

def extract_context(filepath, line_number, context_lines=CONTEXT_LINES):
    """
    Extract a context window around the vulnerable line.
    
    Args:
        filepath: Path to the source file
        line_number: 1-indexed line number of the vulnerability
        context_lines: Number of lines before and after to include
    
    Returns:
        dict with 'before', 'target', 'after' line lists and 'full' context string
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {
            "before": [],
            "target": f"# ERROR: File not found: {filepath}",
            "after": [],
            "full": f"# ERROR: Could not read {filepath}"
        }
    
    total_lines = len(lines)
    idx = line_number - 1  # Convert to 0-indexed
    
    # Calculate range
    start = max(0, idx - context_lines)
    end = min(total_lines, idx + context_lines + 1)
    
    before = lines[start:idx]
    target = lines[idx] if idx < total_lines else ""
    after = lines[idx + 1:end] if idx + 1 < total_lines else []
    
    # Build full context with line numbers
    context_lines_numbered = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = " >> " if i == line_number else "    "
        context_lines_numbered.append(f"{i:4d}{marker}{line.rstrip()}")
    
    return {
        "before": [l.rstrip() for l in before],
        "target": target.rstrip(),
        "after": [l.rstrip() for l in after],
        "full": "\n".join(context_lines_numbered),
        "start_line": start + 1,
        "end_line": end
    }


# =============================================================================
# FIX ENGINE
# =============================================================================

def get_standard_fix(algo, method, bits):
    """
    Look up a standard fix from the rule dictionary.
    
    Args:
        algo: Algorithm name (RSA, AES, etc.)
        method: Method name (generate, new, etc.)
        bits: Key size in bits (or None)
    
    Returns:
        Fix dictionary or None if no standard fix exists
    """
    # Try exact match first
    key = (algo.upper(), method.lower(), bits)
    if key in STANDARD_FIXES:
        return STANDARD_FIXES[key]
    
    # Try without bits (for general fixes)
    key_general = (algo.upper(), method.lower(), None)
    if key_general in STANDARD_FIXES:
        return STANDARD_FIXES[key_general]
    
    return None


def ask_llm_for_fix(code_snippet, finding):
    """
    Skeleton for LLM-based fix generation.
    
    In production, this would call OpenAI/Gemini/Claude API with a prompt like:
    
    "You are a cryptography security expert. The following code has a vulnerability:
    
    {code_snippet}
    
    The vulnerability is: {finding['algo']} with {finding['bits']} bits is {finding['risk']}.
    
    Provide a secure replacement code snippet following NIST guidelines."
    
    Args:
        code_snippet: The vulnerable code context
        finding: The CBOM finding dictionary
    
    Returns:
        Suggested fix string
    """
    # PLACEHOLDER - Replace with actual LLM API call
    # Example implementation:
    #
    # import openai
    # response = openai.ChatCompletion.create(
    #     model="gpt-4",
    #     messages=[
    #         {"role": "system", "content": "You are a cryptography security expert..."},
    #         {"role": "user", "content": f"Fix this vulnerability:\n{code_snippet}"}
    #     ]
    # )
    # return response.choices[0].message.content
    
    algo = finding.get('algo', 'Unknown')
    pqc_suggestion = PQC_MIGRATIONS.get(algo, "Consult NIST PQC standards")
    
    return f"""# AI-GENERATED FIX (Placeholder)
# TODO: Implement actual LLM call for intelligent fix generation
# 
# For {algo}, consider migrating to:
# {pqc_suggestion}
#
# This is a placeholder. In production:
# 1. Call OpenAI/Gemini API with the code context
# 2. Request a secure replacement following NIST guidelines
# 3. Validate the generated code before applying
"""


def generate_fix(finding, context):
    """
    Generate a fix for a vulnerability finding.
    
    Args:
        finding: CBOM finding dictionary
        context: Extracted context dictionary
    
    Returns:
        dict with suggested fix, reason, and source (rule/ai)
    """
    algo = finding.get('algo', '')
    method = finding.get('method', '')
    bits = finding.get('bits')
    
    # Convert bits to int if possible
    if isinstance(bits, str):
        try:
            bits = int(bits)
        except ValueError:
            bits = None
    
    # Try standard fix first
    standard = get_standard_fix(algo, method, bits)
    
    if standard:
        return {
            "fix": standard["fix"],
            "reason": standard["reason"],
            "reference": standard.get("nist_ref", ""),
            "source": "RULE_ENGINE",
            "confidence": "HIGH"
        }
    
    # Fall back to LLM skeleton
    ai_fix = ask_llm_for_fix(context["full"], finding)
    return {
        "fix": ai_fix,
        "reason": f"No standard fix available for {algo}.{method}. AI-generated suggestion.",
        "reference": "NIST PQC Standards",
        "source": "LLM_SKELETON",
        "confidence": "REVIEW_REQUIRED"
    }


# =============================================================================
# REPORT GENERATOR
# =============================================================================

def generate_remediation_plan(findings, base_path=".", output_path="REMEDIATION_PLAN.md"):
    """
    Generate a Markdown remediation plan from CBOM findings.
    
    Args:
        findings: List of CBOM finding dictionaries
        base_path: Base path for resolving relative file paths
        output_path: Output Markdown file path
    
    Returns:
        Path to generated report
    """
    # Filter to priority risks
    priority_findings = [
        f for f in findings 
        if f.get('risk') in PRIORITY_RISKS
    ]
    
    # Sort by risk level (CRITICAL first)
    priority_findings.sort(
        key=lambda x: PRIORITY_RISKS.index(x.get('risk', 'HIGH'))
    )
    
    # Build report
    lines = []
    
    # Header
    lines.append("# 🛡️ Sentinel-PQC Remediation Plan")
    lines.append("")
    lines.append(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"> Standard: NIST SP 800-208 (Post-Quantum Cryptography)")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    critical_count = sum(1 for f in priority_findings if f.get('risk') == 'CRITICAL')
    high_count = sum(1 for f in priority_findings if f.get('risk') == 'HIGH')
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| 🔴 CRITICAL Vulnerabilities | {critical_count} |")
    lines.append(f"| 🟡 HIGH Vulnerabilities | {high_count} |")
    lines.append(f"| **Total Requiring Remediation** | **{len(priority_findings)}** |")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Individual Findings
    lines.append("## Detailed Remediation Steps")
    lines.append("")
    
    for i, finding in enumerate(priority_findings, 1):
        filepath = finding.get('file', 'unknown')
        filename = Path(filepath).name
        line = finding.get('line', '?')
        algo = finding.get('algo', 'Unknown')
        bits = finding.get('bits', 'Unknown')
        risk = finding.get('risk', 'UNKNOWN')
        context_str = finding.get('context', '')
        
        # Risk emoji
        risk_emoji = "🔴" if risk == "CRITICAL" else "🟡"
        
        # Extract context
        full_path = os.path.join(base_path, filepath)
        context = extract_context(full_path, line)
        
        # Generate fix
        fix_result = generate_fix(finding, context)
        
        # Write finding section
        lines.append(f"### {risk_emoji} Vulnerability {i}: {algo}-{bits} in `{filename}`")
        lines.append("")
        lines.append(f"**Location:** `{filepath}` (Line {line})")
        lines.append(f"**Risk Level:** {risk}")
        lines.append(f"**Fix Source:** {fix_result['source']} ({fix_result['confidence']})")
        lines.append("")
        
        lines.append("**Original Code:**")
        lines.append("```python")
        lines.append(context["full"])
        lines.append("```")
        lines.append("")
        
        lines.append("**Sentinel Suggested Fix:**")
        lines.append("```python")
        lines.append(fix_result["fix"])
        lines.append("```")
        lines.append("")
        
        lines.append(f"**Rationale:** {fix_result['reason']}")
        lines.append("")
        if fix_result.get('reference'):
            lines.append(f"**Reference:** {fix_result['reference']}")
            lines.append("")
        
        lines.append("---")
        lines.append("")
    
    # PQC Migration Roadmap
    lines.append("## 🚀 Post-Quantum Migration Roadmap")
    lines.append("")
    lines.append("| Current Algorithm | PQC Replacement | Timeline |")
    lines.append("|-------------------|-----------------|----------|")
    lines.append("| RSA (Key Exchange) | ML-KEM (Kyber-768/1024) | 2025-2030 |")
    lines.append("| RSA/DSA (Signatures) | ML-DSA (Dilithium) | 2025-2030 |")
    lines.append("| ECDSA/ECDH | Hybrid (ECC + ML-KEM) | 2024-2025 |")
    lines.append("| AES-128 | AES-256 (Grover's mitigation) | Immediate |")
    lines.append("")
    lines.append("> **Source:** NIST CNSA 2.0 Suite, NIST SP 800-208")
    lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Generated by Sentinel-PQC Remediator v1.0*")
    
    # Write to file
    report_content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    return output_path


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel-PQC Remediator: Generate remediation plans for crypto vulnerabilities"
    )
    parser.add_argument(
        "--cbom", "-c",
        default="cbom_output.json",
        help="Path to CBOM findings JSON (default: cbom_output.json)"
    )
    parser.add_argument(
        "--output", "-o",
        default="REMEDIATION_PLAN.md",
        help="Output Markdown file (default: REMEDIATION_PLAN.md)"
    )
    parser.add_argument(
        "--base-path", "-b",
        default=".",
        help="Base path for resolving file paths in findings"
    )
    
    args = parser.parse_args()
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                  SENTINEL-PQC REMEDIATOR                          ║
║            AI-Powered Cryptographic Fix Engine                    ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Load CBOM
    print(f"📂 Loading CBOM from: {args.cbom}")
    try:
        with open(args.cbom, "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: CBOM file not found: {args.cbom}")
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in CBOM: {e}")
        return 1
    
    print(f"📊 Found {len(findings)} total findings")
    
    # Filter priority
    priority = [f for f in findings if f.get('risk') in PRIORITY_RISKS]
    print(f"🔴 {len(priority)} require immediate remediation")
    
    # Generate report
    print(f"\n🔧 Generating remediation plan...")
    output = generate_remediation_plan(
        findings, 
        base_path=args.base_path,
        output_path=args.output
    )
    
    print(f"\n✅ Remediation plan saved to: {output}")
    print(f"\n💡 Next steps:")
    print(f"   1. Review the generated fixes")
    print(f"   2. Test each fix in a development environment")
    print(f"   3. Update your cryptographic libraries")
    print(f"   4. Re-run the scanner to verify fixes")
    
    return 0


if __name__ == "__main__":
    exit(main())
