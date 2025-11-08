package domain

import (
	"bytes"
	"os"
)

// FileSignature represents a file type signature (magic bytes)
type FileSignature struct {
	Extension   string
	MagicBytes  []byte
	Offset      int // Offset from start of file
	Description string
}

// Common file signatures for high-entropy formats
// These are naturally compressed formats that should have high entropy
var FileSignatures = []FileSignature{
	// Video formats
	{Extension: ".mp4", MagicBytes: []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, Offset: 0, Description: "MP4 video (ftyp)"},
	{Extension: ".mp4", MagicBytes: []byte{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}, Offset: 0, Description: "MP4 video (ftyp)"},
	{Extension: ".mp4", MagicBytes: []byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, Offset: 0, Description: "MP4 video (ftyp)"},
	{Extension: ".avi", MagicBytes: []byte{0x52, 0x49, 0x46, 0x46}, Offset: 0, Description: "AVI video (RIFF)"},
	{Extension: ".mkv", MagicBytes: []byte{0x1A, 0x45, 0xDF, 0xA3}, Offset: 0, Description: "Matroska video"},
	{Extension: ".mov", MagicBytes: []byte{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70}, Offset: 0, Description: "QuickTime MOV"},
	{Extension: ".wmv", MagicBytes: []byte{0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11}, Offset: 0, Description: "Windows Media Video"},
	{Extension: ".flv", MagicBytes: []byte{0x46, 0x4C, 0x56, 0x01}, Offset: 0, Description: "Flash Video"},
	{Extension: ".webm", MagicBytes: []byte{0x1A, 0x45, 0xDF, 0xA3}, Offset: 0, Description: "WebM video"},

	// Image formats
	{Extension: ".jpg", MagicBytes: []byte{0xFF, 0xD8, 0xFF}, Offset: 0, Description: "JPEG image"},
	{Extension: ".jpeg", MagicBytes: []byte{0xFF, 0xD8, 0xFF}, Offset: 0, Description: "JPEG image"},
	{Extension: ".png", MagicBytes: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, Offset: 0, Description: "PNG image"},
	{Extension: ".gif", MagicBytes: []byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, Offset: 0, Description: "GIF87a"},
	{Extension: ".gif", MagicBytes: []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, Offset: 0, Description: "GIF89a"},
	{Extension: ".bmp", MagicBytes: []byte{0x42, 0x4D}, Offset: 0, Description: "BMP image"},
	{Extension: ".webp", MagicBytes: []byte{0x52, 0x49, 0x46, 0x46}, Offset: 0, Description: "WebP image (RIFF)"},
	{Extension: ".tiff", MagicBytes: []byte{0x49, 0x49, 0x2A, 0x00}, Offset: 0, Description: "TIFF (little-endian)"},
	{Extension: ".tiff", MagicBytes: []byte{0x4D, 0x4D, 0x00, 0x2A}, Offset: 0, Description: "TIFF (big-endian)"},
	{Extension: ".ico", MagicBytes: []byte{0x00, 0x00, 0x01, 0x00}, Offset: 0, Description: "ICO image"},

	// Audio formats
	{Extension: ".mp3", MagicBytes: []byte{0xFF, 0xFB}, Offset: 0, Description: "MP3 audio (MPEG-1 Layer 3)"},
	{Extension: ".mp3", MagicBytes: []byte{0x49, 0x44, 0x33}, Offset: 0, Description: "MP3 with ID3v2 tag"},
	{Extension: ".flac", MagicBytes: []byte{0x66, 0x4C, 0x61, 0x43}, Offset: 0, Description: "FLAC audio"},
	{Extension: ".wav", MagicBytes: []byte{0x52, 0x49, 0x46, 0x46}, Offset: 0, Description: "WAV audio (RIFF)"},
	{Extension: ".ogg", MagicBytes: []byte{0x4F, 0x67, 0x67, 0x53}, Offset: 0, Description: "OGG audio"},
	{Extension: ".m4a", MagicBytes: []byte{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, Offset: 0, Description: "M4A audio"},

	// Archive formats
	{Extension: ".zip", MagicBytes: []byte{0x50, 0x4B, 0x03, 0x04}, Offset: 0, Description: "ZIP archive"},
	{Extension: ".zip", MagicBytes: []byte{0x50, 0x4B, 0x05, 0x06}, Offset: 0, Description: "ZIP (empty)"},
	{Extension: ".zip", MagicBytes: []byte{0x50, 0x4B, 0x07, 0x08}, Offset: 0, Description: "ZIP (spanned)"},
	{Extension: ".rar", MagicBytes: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, Offset: 0, Description: "RAR v1.5+"},
	{Extension: ".rar", MagicBytes: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, Offset: 0, Description: "RAR v5.0+"},
	{Extension: ".7z", MagicBytes: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Offset: 0, Description: "7-Zip archive"},
	{Extension: ".gz", MagicBytes: []byte{0x1F, 0x8B, 0x08}, Offset: 0, Description: "GZIP compressed"},
	{Extension: ".tar", MagicBytes: []byte{0x75, 0x73, 0x74, 0x61, 0x72}, Offset: 257, Description: "TAR archive"},
	{Extension: ".bz2", MagicBytes: []byte{0x42, 0x5A, 0x68}, Offset: 0, Description: "BZIP2 compressed"},
	{Extension: ".xz", MagicBytes: []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, Offset: 0, Description: "XZ compressed"},
	{Extension: ".cab", MagicBytes: []byte{0x4D, 0x53, 0x43, 0x46}, Offset: 0, Description: "Microsoft Cabinet"},
}

// VerifyFileSignature checks if a file's magic bytes match its extension
// Returns true if file signature matches extension (legitimate file)
// Returns false if signature doesn't match (possible fake/encrypted file)
func VerifyFileSignature(filePath string, extension string) (bool, string) {
	// Read first 512 bytes (enough for all signatures)
	file, err := os.Open(filePath)
	if err != nil {
		return false, "cannot_read_file"
	}
	defer file.Close()

	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil && n == 0 {
		return false, "empty_file"
	}

	// Get signatures for this extension
	var matchingSigs []FileSignature
	for _, sig := range FileSignatures {
		if sig.Extension == extension {
			matchingSigs = append(matchingSigs, sig)
		}
	}

	// If no signatures defined for this extension, assume it's OK
	// (We only verify extensions that should have specific signatures)
	if len(matchingSigs) == 0 {
		return true, "no_signature_defined"
	}

	// Check if any signature matches
	for _, sig := range matchingSigs {
		// Check if we have enough bytes to check this signature
		if n < sig.Offset+len(sig.MagicBytes) {
			continue
		}

		// Extract bytes at the signature offset
		fileBytes := header[sig.Offset : sig.Offset+len(sig.MagicBytes)]

		// Compare with expected magic bytes
		if bytes.Equal(fileBytes, sig.MagicBytes) {
			return true, sig.Description
		}
	}

	// No matching signature found - file is likely fake/encrypted
	return false, "signature_mismatch"
}

// IsNaturallyHighEntropyExtension checks if an extension is expected to have high entropy
// (compressed formats like video, images, archives)
func IsNaturallyHighEntropyExtension(extension string) bool {
	naturallyHighEntropy := map[string]bool{
		// Video formats
		".mp4": true, ".avi": true, ".mkv": true, ".mov": true, ".wmv": true,
		".flv": true, ".webm": true, ".m4v": true, ".mpg": true, ".mpeg": true,
		".m2v": true, ".3gp": true, ".3g2": true, ".mts": true, ".m2ts": true,

		// Image formats
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
		".bmp": true, ".tiff": true, ".tif": true, ".ico": true, ".heic": true,
		".heif": true, ".svg": true, ".psd": true, ".raw": true, ".cr2": true,

		// Audio formats
		".mp3": true, ".m4a": true, ".flac": true, ".wav": true, ".ogg": true,
		".aac": true, ".wma": true, ".opus": true, ".ape": true, ".alac": true,

		// Archive formats
		".zip": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true,
		".bz2": true, ".xz": true, ".cab": true, ".iso": true, ".dmg": true,
		".pkg": true, ".deb": true, ".rpm": true,

		// Executable/Binary formats (naturally have some compression)
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
	}

	return naturallyHighEntropy[extension]
}

// GetExpectedFileType returns what type of file we expect based on extension
func GetExpectedFileType(extension string) string {
	switch extension {
	case ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg":
		return "video"
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".ico":
		return "image"
	case ".mp3", ".m4a", ".flac", ".wav", ".ogg", ".aac", ".wma":
		return "audio"
	case ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab":
		return "archive"
	case ".exe", ".dll", ".so", ".dylib":
		return "binary"
	default:
		return "unknown"
	}
}
