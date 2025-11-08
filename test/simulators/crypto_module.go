package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// CryptoModule defines the interface for encryption algorithms
// Implement this interface to create custom encryption modules
type CryptoModule interface {
	// GetName returns the name of the encryption algorithm
	GetName() string

	// Encrypt encrypts the given plaintext and returns ciphertext
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts the given ciphertext and returns plaintext
	Decrypt(ciphertext []byte) ([]byte, error)

	// GetFileExtension returns the extension to add to encrypted files
	GetFileExtension() string
}

// =============================================================================
// AES-256-GCM Encryption Module
// =============================================================================

// AESModule implements AES-256-GCM encryption
type AESModule struct {
	key []byte // 32 bytes for AES-256
}

// NewAESModule creates a new AES encryption module with a random key
func NewAESModule() (*AESModule, error) {
	// Generate random 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return &AESModule{key: key}, nil
}

// NewAESModuleWithKey creates an AES module with a specific key
func NewAESModuleWithKey(key []byte) (*AESModule, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d bytes", len(key))
	}
	return &AESModule{key: key}, nil
}

// NewAESModuleFromPassword creates an AES module from a password (derives key using SHA-256)
func NewAESModuleFromPassword(password string) *AESModule {
	hash := sha256.Sum256([]byte(password))
	return &AESModule{key: hash[:]}
}

func (a *AESModule) GetName() string {
	return "AES-256-GCM"
}

func (a *AESModule) GetFileExtension() string {
	return ".omega"
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns: [nonce (12 bytes)][ciphertext + auth tag]
func (a *AESModule) Encrypt(plaintext []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes for GCM
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (a *AESModule) Decrypt(ciphertext []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GetKey returns the encryption key (for key storage/export)
func (a *AESModule) GetKey() []byte {
	return a.key
}

// =============================================================================
// Pseudo-Random Encryption Module (for testing, high entropy)
// =============================================================================

// PseudoRandomModule generates cryptographically random data
// This is NOT real encryption - just high-entropy data for testing
type PseudoRandomModule struct{}

func NewPseudoRandomModule() *PseudoRandomModule {
	return &PseudoRandomModule{}
}

func (p *PseudoRandomModule) GetName() string {
	return "Pseudo-Random (Testing Only)"
}

func (p *PseudoRandomModule) GetFileExtension() string {
	return ".encrypted"
}

func (p *PseudoRandomModule) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random data with same size as plaintext
	randomData := make([]byte, len(plaintext))
	if _, err := rand.Read(randomData); err != nil {
		return nil, fmt.Errorf("failed to generate random data: %w", err)
	}
	return randomData, nil
}

func (p *PseudoRandomModule) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("pseudo-random module does not support decryption")
}

// =============================================================================
// Example: Custom XOR Module (Simple example for demonstration)
// =============================================================================

// XORModule implements simple XOR encryption (NOT secure, for demo only)
type XORModule struct {
	key []byte
}

func NewXORModule(password string) *XORModule {
	hash := sha256.Sum256([]byte(password))
	return &XORModule{key: hash[:]}
}

func (x *XORModule) GetName() string {
	return "XOR-256 (Demo Only - NOT Secure)"
}

func (x *XORModule) GetFileExtension() string {
	return ".xor"
}

func (x *XORModule) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ x.key[i%len(x.key)]
	}
	return ciphertext, nil
}

func (x *XORModule) Decrypt(ciphertext []byte) ([]byte, error) {
	// XOR is symmetric
	return x.Encrypt(ciphertext)
}

// =============================================================================
// Module Factory
// =============================================================================

// GetCryptoModule returns a crypto module based on the algorithm name
func GetCryptoModule(algorithm string, password string) (CryptoModule, error) {
	switch algorithm {
	case "aes", "aes-256", "aes-gcm":
		if password != "" {
			return NewAESModuleFromPassword(password), nil
		}
		return NewAESModule()

	case "pseudo-random", "random":
		return NewPseudoRandomModule(), nil

	case "xor":
		if password == "" {
			password = "default-xor-key-not-secure"
		}
		return NewXORModule(password), nil

	default:
		return nil, fmt.Errorf("unknown algorithm: %s (supported: aes, pseudo-random, xor)", algorithm)
	}
}

// ListAvailableModules returns a list of available encryption modules
func ListAvailableModules() []string {
	return []string{
		"aes         - AES-256-GCM (default, secure)",
		"pseudo-random - High-entropy random data (testing)",
		"xor         - Simple XOR (demo, not secure)",
	}
}
