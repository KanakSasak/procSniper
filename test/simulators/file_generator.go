package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileGenerator generates test files with realistic content for ransomware simulation
type FileGenerator struct {
	targetDir        string
	fileCount        int
	filesPerSecond   int
	extensionVariety bool
	sizeVariety      bool
	createReadme     bool
}

// File size ranges (in KB)
type fileSizeRange struct {
	minKB int
	maxKB int
	name  string
}

var fileSizeRanges = []fileSizeRange{
	{1, 10, "tiny"},       // 1-10 KB
	{10, 50, "small"},     // 10-50 KB
	{50, 200, "medium"},   // 50-200 KB
	{200, 500, "large"},   // 200-500 KB
	{500, 1000, "xlarge"}, // 500-1000 KB
}

func main() {
	gen := &FileGenerator{}

	flag.StringVar(&gen.targetDir, "dir", "", "Target directory for file generation (REQUIRED)")
	flag.IntVar(&gen.fileCount, "count", 100, "Number of files to generate")
	flag.IntVar(&gen.filesPerSecond, "rate", 50, "Files per second")
	flag.BoolVar(&gen.extensionVariety, "varied-extensions", true, "Use various Windows file extensions")
	flag.BoolVar(&gen.sizeVariety, "varied-sizes", true, "Use various file sizes (1KB-1000KB)")
	flag.BoolVar(&gen.createReadme, "readme", false, "Create README with file inventory")

	flag.Parse()

	if gen.targetDir == "" {
		log.Fatal("ERROR: -dir flag is required. Specify target directory.")
	}

	// Safety check
	if !isSafeDirectory(gen.targetDir) {
		log.Fatalf("ERROR: Directory '%s' is not safe. Use an isolated test directory with 'test', 'sim', 'demo', or 'malware' in path.", gen.targetDir)
	}

	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FILE GENERATOR v1.0                           ║")
	fmt.Println("║        FOR RANSOMWARE TESTING - PART 1 OF 2                ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Target Directory: %s\n", gen.targetDir)
	fmt.Printf("File Count: %d\n", gen.fileCount)
	fmt.Printf("Generation Rate: %d files/sec (%.0f files/min)\n", gen.filesPerSecond, float64(gen.filesPerSecond)*60)
	fmt.Printf("Varied Extensions: %v\n", gen.extensionVariety)
	fmt.Printf("Varied Sizes: %v\n", gen.sizeVariety)
	fmt.Println()

	// Confirm execution
	fmt.Print("Continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "yes" {
		log.Fatal("Operation cancelled")
	}

	gen.Run()
}

func (gen *FileGenerator) Run() {
	startTime := time.Now()

	fmt.Println("\n[*] Starting file generation...")
	fmt.Printf("[*] PID: %d\n", os.Getpid())
	fmt.Println()

	// Create target directory
	if err := os.MkdirAll(gen.targetDir, 0755); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	generatedFiles := gen.generateFiles()

	// Create file inventory
	if gen.createReadme {
		gen.createInventoryFile(generatedFiles)
	}

	// Print summary
	duration := time.Since(startTime)
	gen.printSummary(generatedFiles, duration)
}

func (gen *FileGenerator) generateFiles() []string {
	startTime := time.Now()
	generatedFiles := make([]string, 0, gen.fileCount)

	// Calculate delay between files
	delayNS := time.Second / time.Duration(gen.filesPerSecond)

	for i := 0; i < gen.fileCount; i++ {
		// Generate file metadata
		extension := gen.getExtension(i)
		fileName := fmt.Sprintf("file_%05d%s", i, extension)
		filePath := filepath.Join(gen.targetDir, fileName)
		fileSize := gen.getFileSize(i)

		// Generate file content
		content := gen.generateFileContent(extension, fileSize, i)

		// Write file to disk
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			log.Printf("[!] Failed to create file %s: %v", filePath, err)
			continue
		}

		generatedFiles = append(generatedFiles, filePath)

		// Progress indicator
		if (i+1)%20 == 0 || (i+1) == gen.fileCount {
			elapsed := time.Since(startTime)
			rate := float64(i+1) / elapsed.Seconds() * 60
			fmt.Printf("[*] Generated: %d/%d files (%.0f files/min) - %s (%d KB)\n",
				i+1, gen.fileCount, rate, fileName, fileSize/1024)
		}

		// Rate limiting
		time.Sleep(delayNS)
	}

	return generatedFiles
}

func (gen *FileGenerator) getExtension(index int) string {
	if !gen.extensionVariety {
		return ".txt"
	}

	// Weighted distribution: 40% docs, 30% images, 20% data, 10% media
	r := rand.Float64()

	if r < 0.40 {
		// Documents (40%)
		docs := []string{".txt", ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx"}
		return docs[rand.Intn(len(docs))]
	} else if r < 0.70 {
		// Images (30%)
		images := []string{".jpg", ".jpeg", ".png", ".bmp", ".gif"}
		return images[rand.Intn(len(images))]
	} else if r < 0.90 {
		// Data files (20%)
		data := []string{".csv", ".xml", ".json", ".sql", ".db", ".log"}
		return data[rand.Intn(len(data))]
	} else {
		// Media/Archives (10%)
		media := []string{".mp3", ".mp4", ".avi", ".zip", ".rar"}
		return media[rand.Intn(len(media))]
	}
}

func (gen *FileGenerator) getFileSize(index int) int {
	if !gen.sizeVariety {
		return 10 * 1024 // 10KB default
	}

	// Weighted distribution
	r := rand.Float64()

	var sizeRange fileSizeRange
	if r < 0.30 {
		sizeRange = fileSizeRanges[0] // tiny
	} else if r < 0.60 {
		sizeRange = fileSizeRanges[1] // small
	} else if r < 0.85 {
		sizeRange = fileSizeRanges[2] // medium
	} else if r < 0.95 {
		sizeRange = fileSizeRanges[3] // large
	} else {
		sizeRange = fileSizeRanges[4] // xlarge
	}

	sizeKB := sizeRange.minKB + rand.Intn(sizeRange.maxKB-sizeRange.minKB+1)
	return sizeKB * 1024
}

func (gen *FileGenerator) generateFileContent(extension string, sizeBytes int, index int) []byte {
	switch extension {
	case ".txt", ".log", ".csv", ".xml", ".json", ".sql", ".ini", ".cfg":
		return generateTextContent(sizeBytes, index)
	case ".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx":
		return generateDocumentContent(sizeBytes, index)
	case ".jpg", ".jpeg":
		return generateJPEGContent(sizeBytes)
	case ".png":
		return generatePNGContent(sizeBytes)
	case ".gif":
		return generateGIFContent(sizeBytes)
	case ".bmp":
		return generateBMPContent(sizeBytes)
	case ".mp3":
		return generateMP3Content(sizeBytes)
	case ".mp4":
		return generateMP4Content(sizeBytes)
	case ".avi":
		return generateAVIContent(sizeBytes)
	case ".zip":
		return generateZIPContent(sizeBytes)
	case ".rar":
		return generateRARContent(sizeBytes)
	default:
		return generateTextContent(sizeBytes, index)
	}
}

func generateTextContent(sizeBytes int, index int) []byte {
	header := fmt.Sprintf("Document #%d\nCreated: %s\nType: Text File\n\n",
		index, time.Now().Format(time.RFC3339))

	loremIpsum := `Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
Duis aute irure dolor in reprehenderit in voluptate velit esse cillum.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia.
Deserunt mollit anim id est laborum et dolorum fuga et harum quidem.
`

	content := []byte(header)
	for len(content) < sizeBytes {
		content = append(content, []byte(loremIpsum)...)
	}

	return content[:sizeBytes]
}

func generateDocumentContent(sizeBytes int, index int) []byte {
	header := fmt.Sprintf("DOCUMENT_%05d\x00\x00\x00", index)
	content := []byte(header)

	textPortion := int(float64(sizeBytes) * 0.7)
	binaryPortion := sizeBytes - textPortion

	textContent := generateTextContent(textPortion, index)
	content = append(content, textContent...)

	for i := 0; i < binaryPortion; i++ {
		content = append(content, byte(i%64))
	}

	return content[:sizeBytes]
}

// generateJPEGContent creates a file with valid JPEG magic bytes
func generateJPEGContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// JPEG magic bytes: FF D8 FF
	magicBytes := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46}
	copy(content, magicBytes)

	// Fill rest with low-entropy repetitive pattern
	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generatePNGContent creates a file with valid PNG magic bytes
func generatePNGContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
	magicBytes := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateGIFContent creates a file with valid GIF magic bytes
func generateGIFContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// GIF89a magic bytes: 47 49 46 38 39 61
	magicBytes := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateBMPContent creates a file with valid BMP magic bytes
func generateBMPContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// BMP magic bytes: 42 4D (BM)
	magicBytes := []byte{0x42, 0x4D}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateMP3Content creates a file with valid MP3 magic bytes
func generateMP3Content(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// MP3 with ID3v2 tag: 49 44 33 (ID3)
	magicBytes := []byte{0x49, 0x44, 0x33, 0x03, 0x00}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateMP4Content creates a file with valid MP4 magic bytes
func generateMP4Content(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// MP4 magic bytes: 00 00 00 18 66 74 79 70 (ftyp)
	magicBytes := []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateAVIContent creates a file with valid AVI magic bytes
func generateAVIContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// AVI magic bytes: 52 49 46 46 (RIFF)
	magicBytes := []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x41, 0x56, 0x49, 0x20}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateZIPContent creates a file with valid ZIP magic bytes
func generateZIPContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// ZIP magic bytes: 50 4B 03 04 (PK)
	magicBytes := []byte{0x50, 0x4B, 0x03, 0x04}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// generateRARContent creates a file with valid RAR magic bytes
func generateRARContent(sizeBytes int) []byte {
	content := make([]byte, sizeBytes)

	// RAR v5.0+ magic bytes: 52 61 72 21 1A 07 01 00 (Rar!)
	magicBytes := []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}
	copy(content, magicBytes)

	fillLowEntropyPattern(content, len(magicBytes))

	return content
}

// fillLowEntropyPattern fills the content with low-entropy repetitive pattern
// This creates realistic file structure with LOW entropy (3-5 bits/byte)
func fillLowEntropyPattern(content []byte, startPos int) {
	blockSize := 256
	currentByte := byte(0x20) // Start with space character

	for i := startPos; i < len(content); i++ {
		// Change byte value every blockSize bytes (creates repetitive blocks)
		if (i-startPos)%blockSize == 0 {
			currentByte = byte(((i - startPos) / blockSize) % 32) // Only 32 different values (low entropy)
		}
		content[i] = currentByte
	}
}

func (gen *FileGenerator) createInventoryFile(files []string) {
	inventoryPath := filepath.Join(gen.targetDir, "FILE_INVENTORY.txt")

	var sb strings.Builder
	sb.WriteString("╔════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║              FILE INVENTORY                                ║\n")
	sb.WriteString("╚════════════════════════════════════════════════════════════╝\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Total Files: %d\n\n", len(files)))
	sb.WriteString("Files:\n")
	sb.WriteString("------\n")

	for i, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		sb.WriteString(fmt.Sprintf("%d. %s (%d KB)\n", i+1, filepath.Base(file), info.Size()/1024))
	}

	os.WriteFile(inventoryPath, []byte(sb.String()), 0644)
	fmt.Printf("[*] Created inventory: %s\n", inventoryPath)
}

func (gen *FileGenerator) printSummary(files []string, duration time.Duration) {
	actualRate := float64(len(files)) / duration.Seconds() * 60

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              FILE GENERATION COMPLETE                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Printf("Files Generated: %d\n", len(files))
	fmt.Printf("Duration: %v\n", duration)
	fmt.Printf("Actual Rate: %.0f files/min (%.0f files/sec)\n", actualRate, actualRate/60)
	fmt.Printf("Target Directory: %s\n", gen.targetDir)
	fmt.Println()

	// File statistics
	var totalSize int64
	extCount := make(map[string]int)

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		totalSize += info.Size()
		ext := filepath.Ext(file)
		extCount[ext]++
	}

	fmt.Printf("Total Size: %.2f MB\n", float64(totalSize)/(1024*1024))
	fmt.Printf("File Extensions: %d unique types\n", len(extCount))

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  NEXT STEP                                 ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("Run the file encryptor to encrypt these files:")
	fmt.Printf("  go run file_encryptor.go -dir \"%s\"\n", gen.targetDir)
	fmt.Println()
}

//func isSafeDirectory(dir string) bool {
//	unsafePaths := []string{
//		"C:\\Windows",
//		"C:\\Program Files",
//		"C:\\Users",
//		os.Getenv("USERPROFILE"),
//		os.Getenv("APPDATA"),
//		os.Getenv("TEMP"),
//	}
//
//	absDir, _ := filepath.Abs(dir)
//
//	for _, unsafePath := range unsafePaths {
//		if unsafePath != "" && strings.HasPrefix(absDir, unsafePath) {
//			return false
//		}
//	}
//
//	dirLower := strings.ToLower(filepath.ToSlash(absDir))
//	if !strings.Contains(dirLower, "test") &&
//		!strings.Contains(dirLower, "sim") &&
//		!strings.Contains(dirLower, "demo") &&
//		!strings.Contains(dirLower, "malware") {
//		return false
//	}
//
//	return true
//}
