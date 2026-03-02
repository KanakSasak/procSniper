package infrastructure

import (
	"fmt"
	"net"
	"procSniper/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestSdParamValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", `"simple"`},
		{`has"quote`, `"has\"quote"`},
		{`has\backslash`, `"has\\backslash"`},
		{`has]bracket`, `"has\]bracket"`},
		{`C:\Windows\System32\malware.exe`, `"C:\\Windows\\System32\\malware.exe"`},
		{"", `""`},
	}

	for _, tt := range tests {
		result := sdParamValue(tt.input)
		if result != tt.expected {
			t.Errorf("sdParamValue(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMapThreatToSyslogSeverity(t *testing.T) {
	tests := []struct {
		level    domain.ThreatLevel
		expected SyslogSeverity
	}{
		{domain.ThreatCritical, SevCritical},
		{domain.ThreatHigh, SevError},
		{domain.ThreatMedium, SevWarning},
		{domain.ThreatLow, SevNotice},
		{domain.ThreatNone, SevInfo},
	}

	for _, tt := range tests {
		result := mapThreatToSyslogSeverity(tt.level)
		if result != tt.expected {
			t.Errorf("mapThreatToSyslogSeverity(%q) = %d, want %d", tt.level, result, tt.expected)
		}
	}
}

func TestFormatRFC5424Priority(t *testing.T) {
	client := &SyslogClient{
		config: SyslogConfig{
			Facility: FacilityLocal4, // 20
			Tag:      "procSniper",
		},
		hostname: "TESTHOST",
	}

	alert := domain.NewAlert("RANSOMWARE", domain.ThreatCritical, "guid-123", 1234, `C:\malware.exe`, "Test alert", 85)

	msg := client.formatRFC5424(SevCritical, alert)
	msgStr := string(msg)

	// Priority should be 20*8+2 = 162
	if !strings.HasPrefix(msgStr, "<162>1 ") {
		t.Errorf("Expected priority <162>, got: %s", msgStr[:20])
	}

	// Should contain structured data
	if !strings.Contains(msgStr, `[alert@49152`) {
		t.Error("Missing structured data block")
	}
	if !strings.Contains(msgStr, `category="RANSOMWARE"`) {
		t.Error("Missing category in structured data")
	}
	if !strings.Contains(msgStr, `severity="CRITICAL"`) {
		t.Error("Missing severity in structured data")
	}
	if !strings.Contains(msgStr, `score="85"`) {
		t.Error("Missing score in structured data")
	}
	if !strings.Contains(msgStr, `pid="1234"`) {
		t.Error("Missing pid in structured data")
	}
	// Windows path should have escaped backslashes
	if !strings.Contains(msgStr, `image="C:\\malware.exe"`) {
		t.Errorf("Windows path not escaped properly in: %s", msgStr)
	}
	if !strings.Contains(msgStr, "TESTHOST") {
		t.Error("Missing hostname")
	}
	if !strings.Contains(msgStr, "procSniper") {
		t.Error("Missing app name tag")
	}
	if !strings.Contains(msgStr, "Test alert") {
		t.Error("Missing description message")
	}
}

func TestFormatRFC5424Facilities(t *testing.T) {
	tests := []struct {
		facility SyslogFacility
		severity SyslogSeverity
		expected int
	}{
		{FacilityLocal0, SevCritical, 16*8 + 2},   // 130
		{FacilityLocal4, SevWarning, 20*8 + 4},     // 164
		{FacilityLocal7, SevEmergency, 23*8 + 0},   // 184
		{FacilityAuth, SevError, 4*8 + 3},           // 35
		{FacilityDaemon, SevInfo, 3*8 + 6},          // 30
	}

	for _, tt := range tests {
		client := &SyslogClient{
			config:   SyslogConfig{Facility: tt.facility, Tag: "test"},
			hostname: "host",
		}
		alert := domain.NewAlert("TEST", domain.ThreatLow, "g", 1, "img", "desc", 10)
		msg := string(client.formatRFC5424(tt.severity, alert))
		prefix := fmt.Sprintf("<%d>1 ", tt.expected)
		if !strings.HasPrefix(msg, prefix) {
			t.Errorf("Facility=%d Severity=%d: expected prefix %q, got: %s", tt.facility, tt.severity, prefix, msg[:20])
		}
	}
}

func TestSendAlertUDP(t *testing.T) {
	// Start a local UDP listener
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.LocalAddr().(*net.UDPAddr).Port

	client, err := NewSyslogClient(SyslogConfig{
		Server:   "127.0.0.1",
		Port:     port,
		Protocol: "udp",
		Facility: FacilityLocal4,
		Tag:      "procSniper",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	alert := domain.NewAlert("RANSOMWARE", domain.ThreatHigh, "guid-abc", 5678, `C:\Windows\evil.exe`, "Ransomware detected", 72)

	if err := client.SendAlert(alert); err != nil {
		t.Fatalf("SendAlert failed: %v", err)
	}

	// Read the message from the listener
	buf := make([]byte, 4096)
	listener.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Failed to read from UDP: %v", err)
	}

	msg := string(buf[:n])

	// Verify RFC 5424 format - severity SevError=3, facility Local4=20, pri=163
	if !strings.HasPrefix(msg, "<163>1 ") {
		t.Errorf("Unexpected priority prefix: %s", msg[:20])
	}
	if !strings.Contains(msg, "Ransomware detected") {
		t.Error("Missing alert description in UDP message")
	}
	if !strings.Contains(msg, `category="RANSOMWARE"`) {
		t.Error("Missing category in UDP message")
	}
}

func TestSendAlertTCP(t *testing.T) {
	// Start a local TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	client, err := NewSyslogClient(SyslogConfig{
		Server:   "127.0.0.1",
		Port:     port,
		Protocol: "tcp",
		Facility: FacilityLocal4,
		Tag:      "procSniper",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	alert := domain.NewAlert("STEALER", domain.ThreatCritical, "guid-xyz", 9999, `C:\stealer.exe`, "Credential theft detected", 95)

	if err := client.SendAlert(alert); err != nil {
		t.Fatalf("SendAlert failed: %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "Credential theft detected") {
			t.Errorf("Unexpected TCP message: %s", msg)
		}
		// TCP messages should end with newline
		if !strings.HasSuffix(msg, "\n") {
			t.Error("TCP message should end with newline delimiter")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for TCP message")
	}
}

func TestNewSyslogClientEmptyServer(t *testing.T) {
	_, err := NewSyslogClient(SyslogConfig{
		Server: "",
		Port:   514,
	})
	if err == nil {
		t.Error("Expected error for empty server, got nil")
	}
}

func TestNewSyslogClientConnectionRefused(t *testing.T) {
	// Connect to a port where nothing is listening
	client, err := NewSyslogClient(SyslogConfig{
		Server:   "127.0.0.1",
		Port:     19999,
		Protocol: "tcp",
	})
	// Should not return error — client is created but not connected
	if err != nil {
		t.Fatalf("NewSyslogClient should not fail on connection refusal: %v", err)
	}
	if client == nil {
		t.Fatal("Client should not be nil")
	}
	defer client.Close()

	// SendAlert should fail gracefully
	alert := domain.NewAlert("TEST", domain.ThreatLow, "g", 1, "img", "test", 10)
	err = client.SendAlert(alert)
	if err == nil {
		t.Error("Expected send error when server is unreachable")
	}
}

func TestSendAlertNilAlert(t *testing.T) {
	client := &SyslogClient{
		config: SyslogConfig{Server: "127.0.0.1", Port: 514, Protocol: "udp", Tag: "test"},
	}
	if err := client.SendAlert(nil); err != nil {
		t.Errorf("SendAlert(nil) should return nil, got: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	// Create a UDP client (connection always succeeds)
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	listener, _ := net.ListenUDP("udp", addr)
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port

	client, _ := NewSyslogClient(SyslogConfig{
		Server:   "127.0.0.1",
		Port:     port,
		Protocol: "udp",
	})

	// Close multiple times should not panic
	client.Close()
	client.Close()
	client.Close()
}
