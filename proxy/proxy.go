/*
Sentinel-PQC Proxy - Module B
=============================
Ghost Incompatibility Detector

This proxy simulates a Post-Quantum TLS handshake using Kyber-768 (ML-KEM-768)
and measures the handshake size to detect MTU fragmentation risks.

Architecture:
  1. Client connects and sends Public Key (simulating TLS 1.3 ClientHello KeyShare)
  2. Proxy measures incoming packet size
  3. If size > 1400 bytes: GHOST FRAGMENTATION DETECTED
  4. Proxy completes key exchange by encapsulating and sending ciphertext back

Why 1400 bytes?
  - Standard Ethernet MTU: 1500 bytes
  - IP Header: 20 bytes
  - TCP Header: 20 bytes
  - TLS Record Header: ~5 bytes
  - Safe payload: ~1400 bytes

Kyber-768 Sizes:
  - Public Key: 1184 bytes
  - Ciphertext: 1088 bytes
  - Combined: 2272 bytes > 1400 = GUARANTEED FRAGMENTATION
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

const (
	PROXY_PORT = ":4433"
	SAFE_MTU   = 1400 // Bytes (Standard MTU 1500 - Headers)
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// GhostReport structure for the Dashboard (Module C)
type GhostReport struct {
	Timestamp     string `json:"timestamp"`
	ClientIP      string `json:"client_ip"`
	Algorithm     string `json:"algorithm"`
	PublicKeySize int    `json:"public_key_size"`
	HandshakeSize int    `json:"handshake_size_bytes"`
	Fragmentation bool   `json:"fragmentation_risk"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

func main() {
	printBanner()

	// 1. Setup PQC Scheme (Kyber-768 / ML-KEM-768)
	scheme := schemes.ByName("Kyber768")
	if scheme == nil {
		log.Fatal("Failed to load Kyber768 scheme")
	}

	log.Printf("[SENTINEL] PQC Algorithm: %s", scheme.Name())
	log.Printf("[SENTINEL] Public Key Size: %d bytes", scheme.PublicKeySize())
	log.Printf("[SENTINEL] Ciphertext Size: %d bytes", scheme.CiphertextSize())
	log.Printf("[SENTINEL] Safe MTU Threshold: %d bytes", SAFE_MTU)
	log.Println()

	// 2. Start TCP Listener
	listener, err := net.Listen("tcp", PROXY_PORT)
	if err != nil {
		log.Fatalf("Error starting proxy: %v", err)
	}
	defer listener.Close()

	log.Printf("[SENTINEL] 🛡️  Ghost Proxy Listening on %s", PROXY_PORT)
	log.Println("[SENTINEL] Waiting for PQC handshake simulations...")
	log.Println()

	// 3. Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ERROR] Connection accept failed: %v", err)
			continue
		}
		go handleConnection(conn, scheme)
	}
}

// ============================================================================
// CONNECTION HANDLER
// ============================================================================

func handleConnection(conn net.Conn, scheme kem.Scheme) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().String()

	log.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Printf("[CONN] New Client: %s", clientIP)

	// --- STEP 1: READ CLIENT "HELLO" (Contains PQC Public Key) ---
	// In TLS 1.3, Client sends the Key Share (Public Key) first.
	// This is where fragmentation typically occurs.
	buffer := make([]byte, 4096)

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("[ERROR] Read failed: %v", err)
		}
		return
	}

	// Actual data received (Simulating ClientHello with KeyShare)
	clientData := buffer[:n]
	handshakeSize := len(clientData)

	log.Printf("[METRICS] Received Handshake Packet: %d bytes", handshakeSize)

	// --- STEP 2: GHOST DETECTION LOGIC ---
	isFragmented := handshakeSize > SAFE_MTU
	var status, message string

	if isFragmented {
		status = "CRITICAL_RISK"
		message = fmt.Sprintf("Packet size %d > MTU %d. WILL FRAGMENT on legacy networks!", handshakeSize, SAFE_MTU)
		log.Printf("⚠️  [GHOST DETECTED] %s", message)
	} else {
		status = "SAFE"
		message = fmt.Sprintf("Packet size %d fits within MTU %d", handshakeSize, SAFE_MTU)
		log.Printf("✅ [SAFE] %s", message)
	}

	// --- STEP 3: COMPLETE KEY EXCHANGE ---
	// Extract and validate the Public Key from client payload
	pkSize := scheme.PublicKeySize()
	if len(clientData) < pkSize {
		log.Printf("❌ [ERROR] Payload too small (%d bytes) for Kyber-768 key (%d bytes required)",
			len(clientData), pkSize)
		return
	}

	// Extract Public Key (at start of packet for simulation)
	pkBytes := clientData[:pkSize]
	pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		log.Printf("❌ [ERROR] Invalid Kyber Public Key: %v", err)
		return
	}

	log.Printf("[CRYPTO] Valid Kyber-768 Public Key received")

	// Encapsulate: Generate Shared Secret + Ciphertext
	ct, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		log.Printf("❌ [ERROR] Encapsulation failed: %v", err)
		return
	}

	// The shared secret would be used for symmetric encryption
	_ = ss
	log.Printf("[CRYPTO] Encapsulation complete. Shared secret derived.")
	log.Printf("[CRYPTO] Ciphertext size: %d bytes", len(ct))

	// Send Ciphertext back (simulating ServerHello KeyShare)
	_, err = conn.Write(ct)
	if err != nil {
		log.Printf("[ERROR] Failed to send ciphertext: %v", err)
		return
	}
	log.Printf("[SENT] ServerHello Ciphertext (%d bytes) sent to client", len(ct))

	// --- STEP 4: GENERATE REPORT ---
	report := saveReport(clientIP, scheme.Name(), pkSize, handshakeSize, isFragmented, status, message)
	logReportSummary(report)
}

// ============================================================================
// REPORTING
// ============================================================================

func saveReport(ip, algo string, pkSize, totalSize int, frag bool, status, msg string) GhostReport {
	report := GhostReport{
		Timestamp:     time.Now().Format(time.RFC3339),
		ClientIP:      ip,
		Algorithm:     algo,
		PublicKeySize: pkSize,
		HandshakeSize: totalSize,
		Fragmentation: frag,
		Status:        status,
		Message:       msg,
	}

	// Save to JSON file
	file, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal report: %v", err)
		return report
	}

	err = os.WriteFile("ghost_report.json", file, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to write report: %v", err)
	} else {
		log.Printf("[REPORT] Saved to ghost_report.json")
	}

	return report
}

func logReportSummary(r GhostReport) {
	log.Println()
	log.Println("┌─────────────────────────────────────────────┐")
	log.Println("│           GHOST DETECTION SUMMARY           │")
	log.Println("├─────────────────────────────────────────────┤")
	log.Printf("│ Algorithm:      %-27s │\n", r.Algorithm)
	log.Printf("│ Public Key:     %-27s │\n", fmt.Sprintf("%d bytes", r.PublicKeySize))
	log.Printf("│ Total Size:     %-27s │\n", fmt.Sprintf("%d bytes", r.HandshakeSize))
	log.Printf("│ MTU Threshold:  %-27s │\n", fmt.Sprintf("%d bytes", SAFE_MTU))

	if r.Fragmentation {
		log.Println("│ Status:         ⚠️  FRAGMENTATION RISK       │")
	} else {
		log.Println("│ Status:         ✅ SAFE                      │")
	}
	log.Println("└─────────────────────────────────────────────┘")
	log.Println()
}

// ============================================================================
// UI HELPERS
// ============================================================================

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║                    SENTINEL-PQC GHOST PROXY                       ║
║             Post-Quantum Fragmentation Detector                   ║
╠═══════════════════════════════════════════════════════════════════╣
║  Simulates Kyber-768 (ML-KEM-768) key exchange and detects        ║
║  network fragmentation risks caused by large PQC keys.            ║
╚═══════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
