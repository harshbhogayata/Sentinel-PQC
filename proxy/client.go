/*
Sentinel-PQC Test Client
========================
Simulates a browser/client performing a PQC (Kyber-768) key exchange.

In TLS 1.3 with PQC:
  1. Client generates a Kyber-768 keypair
  2. Client sends Public Key in ClientHello (KeyShare extension)
  3. Server encapsulates and sends Ciphertext in ServerHello
  4. Both derive the same shared secret

This client sends:
  - Kyber-768 Public Key: 1184 bytes
  - Simulated TLS Headers: configurable padding

Change PADDING_SIZE to test fragmentation:
  - 150 bytes → Total 1334 → SAFE (< 1400)
  - 300 bytes → Total 1484 → GHOST DETECTED (> 1400)
*/

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cloudflare/circl/kem/schemes"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

const (
	PROXY_ADDRESS = "127.0.0.1:4433"
	
	// Change this to test different scenarios:
	// 150 = Safe (total 1334 bytes < 1400)
	// 300 = Ghost detected (total 1484 bytes > 1400)
	PADDING_SIZE = 300
)

// ============================================================================
// MAIN
// ============================================================================

func main() {
	printBanner()

	// 1. Initialize Kyber-768 scheme
	scheme := schemes.ByName("Kyber768")
	if scheme == nil {
		log.Fatal("Failed to load Kyber768 scheme")
	}

	log.Printf("[CLIENT] Algorithm: %s", scheme.Name())
	log.Printf("[CLIENT] Target: %s", PROXY_ADDRESS)
	log.Println()

	// 2. Generate Keypair (simulating browser's ephemeral key)
	log.Println("[CRYPTO] Generating Kyber-768 keypair...")
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}

	// Marshal public key to bytes
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	log.Printf("[CRYPTO] Public Key generated: %d bytes", len(pkBytes))
	log.Printf("[CRYPTO] Secret Key stored locally for decapsulation")

	// 3. Connect to Proxy
	log.Println()
	log.Printf("[NETWORK] Connecting to %s...", PROXY_ADDRESS)

	conn, err := net.DialTimeout("tcp", PROXY_ADDRESS, 5*time.Second)
	if err != nil {
		log.Fatalf("❌ Connection failed: %v", err)
	}
	defer conn.Close()

	log.Printf("[NETWORK] ✅ Connected!")

	// 4. Build ClientHello simulation
	// Real TLS ClientHello contains:
	//   - Protocol version, random bytes
	//   - Cipher suites, extensions
	//   - Key Share extension with PQC public key
	// We simulate with: PK + padding for headers
	
	padding := make([]byte, PADDING_SIZE)
	// Fill padding with realistic-looking data
	for i := range padding {
		padding[i] = byte(i % 256)
	}

	payload := append(pkBytes, padding...)
	totalSize := len(payload)

	log.Println()
	log.Println("┌─────────────────────────────────────────────┐")
	log.Println("│          CLIENTHELLO SIMULATION             │")
	log.Println("├─────────────────────────────────────────────┤")
	log.Printf("│ Public Key:     %-27s │\n", fmt.Sprintf("%d bytes", len(pkBytes)))
	log.Printf("│ TLS Headers:    %-27s │\n", fmt.Sprintf("%d bytes (padding)", PADDING_SIZE))
	log.Printf("│ Total Payload:  %-27s │\n", fmt.Sprintf("%d bytes", totalSize))
	log.Println("└─────────────────────────────────────────────┘")

	if totalSize > 1400 {
		log.Println()
		log.Println("⚠️  WARNING: Payload exceeds 1400 bytes - fragmentation expected!")
	}

	// 5. Send ClientHello
	log.Println()
	log.Printf("[SEND] Sending ClientHello (%d bytes)...", totalSize)

	_, err = conn.Write(payload)
	if err != nil {
		log.Fatalf("❌ Send failed: %v", err)
	}
	log.Printf("[SEND] ✅ ClientHello sent successfully")

	// 6. Wait for ServerHello (Ciphertext)
	log.Println()
	log.Println("[RECV] Waiting for ServerHello (ciphertext)...")

	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("❌ Failed to receive ServerHello: %v", err)
		log.Println("   This could indicate:")
		log.Println("   - Proxy rejected the connection")
		log.Println("   - Network dropped fragmented packets")
		log.Println("   - Firewall/NAT interference")
		return
	}

	ciphertext := buffer[:n]
	log.Printf("[RECV] ✅ Received ServerHello: %d bytes", len(ciphertext))

	// 7. Decapsulate (derive shared secret)
	log.Println()
	log.Println("[CRYPTO] Decapsulating to derive shared secret...")

	ss, err := scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		log.Printf("❌ Decapsulation failed: %v", err)
		return
	}

	log.Printf("[CRYPTO] ✅ Shared secret derived: %d bytes", len(ss))
	log.Printf("[CRYPTO] First 8 bytes: %x", ss[:8])

	// 8. Success summary
	log.Println()
	log.Println("╔═══════════════════════════════════════════════════════════════════╗")
	log.Println("║              🎉 PQC HANDSHAKE SIMULATION COMPLETE                 ║")
	log.Println("╠═══════════════════════════════════════════════════════════════════╣")
	log.Println("║  Both client and server now share the same secret key.            ║")
	log.Println("║  In a real TLS session, this would be used for AES encryption.    ║")
	log.Println("╚═══════════════════════════════════════════════════════════════════╝")
}

// ============================================================================
// UI HELPERS
// ============================================================================

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║                  SENTINEL-PQC TEST CLIENT                         ║
║           Kyber-768 Handshake Simulation Tool                     ║
╚═══════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
