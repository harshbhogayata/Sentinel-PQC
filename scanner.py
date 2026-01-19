"""
Sentinel-PQC Scanner - Module A
================================
A Tree-Sitter based static analysis scanner for detecting cryptographic call sites
in Python source code. Identifies vulnerable algorithms and key sizes for 
Post-Quantum Cryptography migration planning.

AST Logic Explained:
--------------------
Unlike regex, Tree-Sitter builds a full Abstract Syntax Tree (AST) of the code.
This means we understand the STRUCTURE of the code, not just text patterns.

For example, when parsing: RSA.generate(bits=2048)

Tree-Sitter produces:
    call
    ├── function (attribute)
    │   ├── object: "RSA"         <- identifier
    │   └── attribute: "generate"  <- method name
    └── arguments (argument_list)
        └── keyword_argument
            ├── name: "bits"
            └── value: 2048       <- integer literal

We traverse this tree recursively looking for 'call' nodes with 'attribute' 
access patterns that match known cryptographic libraries.
"""

import tree_sitter_python
from tree_sitter import Language, Parser
import os
import json


class PQCScanner:
    """
    Post-Quantum Cryptography Scanner using Tree-Sitter AST parsing.
    
    The scanner identifies cryptographic function calls and classifies them
    based on their quantum-vulnerability risk level.
    """
    
    def __init__(self):
        """
        Initialize the Tree-Sitter parser and define target patterns.
        
        STEP 1: Load the Python grammar
        --------------------------------
        tree_sitter_python.language() returns a pointer to the compiled
        Python grammar. We wrap it in Language() to use with the parser.
        """
        self.PY_LANGUAGE = Language(tree_sitter_python.language())
        self.parser = Parser(self.PY_LANGUAGE)
        
        # STEP 2: Target Configuration
        # ----------------------------
        # Maps algorithm names to:
        #   - methods: Which function calls indicate key generation
        #   - arg_keys: Which keyword arguments contain the key size
        #   - aliases: Common import aliases for this library
        self.TARGETS = {
            "RSA": {
                "methods": ["generate", "construct", "new_key"],
                "arg_keys": ["bits", "size", "key_size"],
                "aliases": ["RSA", "PyRSA", "rsa", "_RSA"]
            },
            "DSA": {
                "methods": ["generate", "construct"],
                "arg_keys": ["bits", "key_size"],
                "aliases": ["DSA", "dsa"]
            },
            "AES": {
                "methods": ["new", "encrypt", "decrypt"],
                "arg_keys": ["key", "bits", "key_size"],
                "aliases": ["AES", "Cipher", "aes"]
            },
            "EC": {
                "methods": ["generate", "generate_private_key", "new_key"],
                "arg_keys": ["curve"],
                "aliases": ["EC", "ECC", "ECDSA", "ECDH", "ec"]
            },
            "DES": {
                "methods": ["new"],
                "arg_keys": ["key"],
                "aliases": ["DES", "DES3", "TripleDES"]
            }
        }
        
        # Build reverse lookup: alias -> canonical name
        self._alias_map = {}
        for canonical, config in self.TARGETS.items():
            for alias in config.get("aliases", []):
                self._alias_map[alias] = canonical

    def _get_text(self, node, source_bytes):
        """Extract the source text for a given AST node."""
        return node.text.decode('utf8')

    def _calculate_risk(self, algo, bits):
        """
        Calculate Post-Quantum risk level based on NIST guidelines.
        
        Risk Levels:
        - CRITICAL: Algorithm is already broken or easily breakable
        - HIGH: Vulnerable to known quantum algorithms (Shor's, Grover's)
        - MEDIUM: Reduced security margin in post-quantum world
        - LOW: Considered quantum-resistant or quantum-safe
        """
        algo = algo.upper()
        
        # Handle cases where key size couldn't be extracted
        if not bits or bits == 0:
            return "UNKNOWN"
        
        # RSA Risk Assessment
        # Shor's algorithm breaks RSA in polynomial time
        if algo in ["RSA", "DSA"]:
            if bits < 2048:
                return "CRITICAL"  # Already weak against classical attacks
            if bits < 4096:
                return "HIGH"      # Vulnerable to Shor's algorithm
            return "MEDIUM"        # Still quantum-vulnerable, but better
        
        # AES Risk Assessment  
        # Grover's algorithm provides quadratic speedup (effectively halves key size)
        if algo == "AES":
            if bits == 128:
                return "MEDIUM"    # Reduced to 64-bit effective security
            if bits in [192, 256]:
                return "LOW"       # 96-bit or 128-bit effective security
            return "UNKNOWN"
        
        # ECC Risk Assessment
        # Shor's algorithm breaks all ECC in polynomial time
        if algo in ["EC", "ECC", "ECDSA", "ECDH"]:
            return "HIGH"          # All ECC is quantum-vulnerable
        
        # DES/3DES - already deprecated
        if algo in ["DES", "3DES", "TRIPLEDES"]:
            return "CRITICAL"      # Should not be used at all
        
        # Default: assume high risk for unknown asymmetric crypto
        return "HIGH"

    def _resolve_alias(self, name):
        """
        Resolve an alias to its canonical algorithm name.
        
        Example: PyRSA -> RSA, Cipher -> AES
        """
        return self._alias_map.get(name, name)

    def _extract_key_size(self, args_node, arg_keys):
        """
        Extract key size from function arguments.
        
        Handles two cases:
        1. Positional: RSA.generate(2048)
        2. Keyword: RSA.generate(bits=2048) or RSA.generate(e=65537, bits=2048)
        
        The tricky part is distinguishing key sizes from other integers like
        the public exponent (e=65537). We use heuristics:
        - Key sizes are typically > 64 bits
        - Named arguments matching known keys take priority
        """
        key_size = 0
        
        if not args_node:
            return 0
            
        for child in args_node.children:
            # Case A: Positional Integer Argument
            # -----------------------------------
            # e.g., RSA.generate(2048)
            # We take the first integer that looks like a key size (> 64)
            if child.type == "integer":
                val = int(self._get_text(child, None))
                # Sanity check: RSA keys > 512 bits, AES keys 128/192/256
                # e=65537 is the common RSA exponent, skip it
                if val >= 128 and val != 65537:
                    key_size = val
                    break
            
            # Case B: Keyword Argument
            # ------------------------
            # e.g., RSA.generate(bits=2048) or AES.new(key=b'...', mode=...)
            # keyword_argument node structure:
            #   keyword_argument
            #     name: identifier "bits"
            #     value: integer 2048
            elif child.type == "keyword_argument":
                arg_name_node = child.child_by_field_name("name")
                arg_val_node = child.child_by_field_name("value")
                
                if arg_name_node and arg_val_node:
                    arg_name = self._get_text(arg_name_node, None)
                    
                    # Only extract if this is a known key size parameter
                    if arg_name in arg_keys:
                        if arg_val_node.type == "integer":
                            key_size = int(self._get_text(arg_val_node, None))
                            break
                        # For AES, key might be bytes - estimate from length
                        elif arg_val_node.type in ["string", "binary_string"]:
                            # b'16_byte_key!!!!!' -> 16 bytes = 128 bits
                            key_text = self._get_text(arg_val_node, None)
                            # Remove quotes: b'...' or '...'
                            key_bytes = len(key_text) - 3 if key_text.startswith("b") else len(key_text) - 2
                            key_size = key_bytes * 8
                            break
        
        return key_size

    def _find_calls(self, node, source_code, results):
        """
        Recursively traverse the AST to find function calls.
        
        TRAVERSAL LOGIC:
        1. Check if current node is a 'call' node
        2. If so, extract function (object.method) and arguments
        3. Check if object matches a known crypto library
        4. Check if method is a key-generation function
        5. Extract key size and calculate risk
        6. Add to results if it's a crypto call
        7. Recurse into all child nodes
        """
        # Check if this is a function call
        if node.type == "call":
            # Get the function being called (e.g., RSA.generate)
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            
            # We're looking for attribute access: object.method()
            if func and func.type == "attribute":
                obj_node = func.child_by_field_name("object")
                method_node = func.child_by_field_name("attribute")
                
                if obj_node and method_node:
                    obj_name = self._get_text(obj_node, source_code)
                    method_name = self._get_text(method_node, source_code)
                    
                    # FILTER 1: Is this a known crypto library?
                    # Resolve aliases (e.g., PyRSA -> RSA)
                    canonical_name = self._resolve_alias(obj_name)
                    target_config = self.TARGETS.get(canonical_name)
                    
                    if target_config:
                        # FILTER 2: Is this a key generation method?
                        if method_name in target_config["methods"]:
                            # STEP 5: Extract the key size
                            key_size = self._extract_key_size(
                                args, 
                                target_config["arg_keys"]
                            )
                            
                            # STEP 6: Calculate risk
                            risk = self._calculate_risk(canonical_name, key_size)
                            
                            # STEP 7: Build the finding
                            context = self._get_text(node, source_code)
                            
                            finding = {
                                "file": "",  # Will be set by scan_file
                                "line": node.start_point[0] + 1,  # 1-indexed
                                "algo": canonical_name,
                                "method": method_name,
                                "bits": key_size if key_size else "Unknown",
                                "risk": risk,
                                "context": context[:100]  # Truncate long lines
                            }
                            
                            results.append(finding)
        
        # Recurse into all children
        for child in node.children:
            self._find_calls(child, source_code, results)

    def scan_file(self, filepath):
        """
        Scan a Python file for cryptographic function calls.
        
        ALGORITHM:
        1. Read and parse the source file into an AST
        2. Recursively traverse the tree looking for call nodes
        3. For each matching call, extract: algorithm, method, key size
        4. Calculate risk level and build the finding record
        
        Returns:
            List of findings as dictionaries ready for JSON serialization
        """
        results = []
        
        # STEP 1: Read the source file
        try:
            with open(filepath, 'rb') as f:
                source_code = f.read()
        except Exception as e:
            print(f"[ERROR] Cannot read {filepath}: {e}")
            return []
        
        # STEP 2: Parse into AST
        # The parser.parse() returns a Tree object with a root_node
        tree = self.parser.parse(source_code)
        
        # STEP 3: Traverse and find crypto calls
        self._find_calls(tree.root_node, source_code, results)
        
        # STEP 4: Add file path to all results
        for result in results:
            result["file"] = os.path.normpath(filepath)
        
        return results

    def scan_directory(self, dirpath, extensions=('.py',)):
        """
        Recursively scan a directory for Python files.
        
        Args:
            dirpath: Path to directory to scan
            extensions: Tuple of file extensions to include
            
        Returns:
            List of all findings from all files
        """
        all_results = []
        
        for root, dirs, files in os.walk(dirpath):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                '__pycache__', '.git', 'node_modules', 'venv', '.venv', 'env'
            }]
            
            for file in files:
                if file.endswith(extensions):
                    filepath = os.path.join(root, file)
                    results = self.scan_file(filepath)
                    all_results.extend(results)
        
        return all_results

    def generate_cbom(self, findings, output_path=None):
        """
        Generate a CycloneDX-compatible CBOM (Cryptographic Bill of Materials).
        
        The output follows CycloneDX 1.6 structure for cryptographic assets.
        """
        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "tool": {
                    "vendor": "Sentinel-PQC",
                    "name": "Cryptographic Scanner",
                    "version": "1.0.0"
                }
            },
            "cryptoAssets": []
        }
        
        for finding in findings:
            asset = {
                "type": "algorithm",
                "name": finding["algo"],
                "occurrences": [{
                    "location": finding["file"],
                    "line": finding["line"],
                    "context": finding["context"]
                }],
                "properties": [
                    {"name": "keySize", "value": str(finding["bits"])},
                    {"name": "method", "value": finding["method"]},
                    {"name": "quantumRisk", "value": finding["risk"]}
                ]
            }
            cbom["cryptoAssets"].append(asset)
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(cbom, f, indent=2)
                
        return cbom


# Convenience function for quick scanning
def scan(path):
    """Quick scan helper - accepts file or directory path."""
    scanner = PQCScanner()
    
    if os.path.isfile(path):
        return scanner.scan_file(path)
    elif os.path.isdir(path):
        return scanner.scan_directory(path)
    else:
        raise ValueError(f"Path not found: {path}")
