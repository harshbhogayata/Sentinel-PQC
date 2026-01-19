"""
Sentinel-PQC: Post-Quantum Cryptography Scanner
================================================
CLI entry point for the cryptographic scanner.

Usage:
    python main.py <file_or_directory>
    python main.py test_samples/vulnerable.py
    python main.py . --output cbom.json
"""

import sys
import os
import json
import argparse
from scanner import PQCScanner


def print_banner():
    """Display the scanner banner."""
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                     SENTINEL-PQC SCANNER                         ║
║            Post-Quantum Cryptography Risk Analyzer               ║
╚═══════════════════════════════════════════════════════════════════╝
    """)


def print_finding(finding, index):
    """Pretty-print a single finding."""
    risk_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[94m",    # Blue
        "LOW": "\033[92m",       # Green
        "UNKNOWN": "\033[90m"    # Gray
    }
    reset = "\033[0m"
    
    risk = finding["risk"]
    color = risk_colors.get(risk, "")
    
    print(f"\n[{index}] {color}■ {risk}{reset}")
    print(f"    File: {finding['file']}")
    print(f"    Line: {finding['line']}")
    print(f"    Algorithm: {finding['algo']}.{finding['method']}()")
    print(f"    Key Size: {finding['bits']} bits")
    print(f"    Context: {finding['context']}")


def print_summary(findings):
    """Print a summary of all findings by risk level."""
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    
    for f in findings:
        risk = f["risk"]
        if risk in risk_counts:
            risk_counts[risk] += 1
        else:
            risk_counts["UNKNOWN"] += 1
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  🔴 CRITICAL: {risk_counts['CRITICAL']}")
    print(f"  🟡 HIGH:     {risk_counts['HIGH']}")
    print(f"  🔵 MEDIUM:   {risk_counts['MEDIUM']}")
    print(f"  🟢 LOW:      {risk_counts['LOW']}")
    print(f"  ⚪ UNKNOWN:  {risk_counts['UNKNOWN']}")
    print("-" * 60)
    print(f"  TOTAL:       {len(findings)} cryptographic call sites")
    
    # Calculate quantum readiness score
    vulnerable = risk_counts['CRITICAL'] + risk_counts['HIGH']
    total = len(findings) or 1
    score = max(0, 100 - (vulnerable / total * 100))
    
    print(f"\n  📊 QUANTUM READINESS SCORE: {score:.1f}%")
    if score < 50:
        print("     ⚠️  URGENT: Your codebase has significant quantum vulnerabilities!")
    elif score < 80:
        print("     ⚡ CAUTION: Some cryptographic updates are recommended.")
    else:
        print("     ✅ GOOD: Your codebase is mostly quantum-ready.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Sentinel-PQC: Scan source code for cryptographic vulnerabilities"
    )
    parser.add_argument(
        "path",
        help="File or directory to scan"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON file path (default: cbom_output.json)",
        default="cbom_output.json"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress detailed output, only show summary"
    )
    parser.add_argument(
        "--cbom",
        action="store_true",
        help="Generate CycloneDX CBOM format output"
    )
    
    args = parser.parse_args()
    
    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)
    
    print_banner()
    
    # Initialize scanner
    scanner = PQCScanner()
    
    # Run the scan
    print(f"🔍 Scanning: {os.path.abspath(args.path)}")
    print("-" * 60)
    
    if os.path.isfile(args.path):
        findings = scanner.scan_file(args.path)
    else:
        findings = scanner.scan_directory(args.path)
    
    if not findings:
        print("\n✅ No cryptographic call sites detected!")
        return
    
    # Print detailed findings
    if not args.quiet:
        for i, finding in enumerate(findings, 1):
            print_finding(finding, i)
    
    # Print summary
    print_summary(findings)
    
    # Save output
    if args.cbom:
        output = scanner.generate_cbom(findings, args.output)
        print(f"\n📄 CycloneDX CBOM saved to: {args.output}")
    else:
        with open(args.output, 'w') as f:
            json.dump(findings, f, indent=2)
        print(f"\n📄 Findings saved to: {args.output}")


if __name__ == "__main__":
    main()
