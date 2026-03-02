package infrastructure

import (
	"fmt"
	"log"
	"net"
	"os"
	"procSniper/internal/domain"
	"strings"
	"sync"
	"time"
)

// SyslogFacility represents the syslog facility code (RFC 5424).
type SyslogFacility int

const (
	FacilityKern   SyslogFacility = 0
	FacilityUser   SyslogFacility = 1
	FacilityDaemon SyslogFacility = 3
	FacilityAuth   SyslogFacility = 4
	FacilitySyslog SyslogFacility = 5
	FacilityLocal0 SyslogFacility = 16
	FacilityLocal1 SyslogFacility = 17
	FacilityLocal2 SyslogFacility = 18
	FacilityLocal3 SyslogFacility = 19
	FacilityLocal4 SyslogFacility = 20
	FacilityLocal5 SyslogFacility = 21
	FacilityLocal6 SyslogFacility = 22
	FacilityLocal7 SyslogFacility = 23
)

// SyslogSeverity maps to RFC 5424 severity levels.
type SyslogSeverity int

const (
	SevEmergency SyslogSeverity = 0
	SevAlert     SyslogSeverity = 1
	SevCritical  SyslogSeverity = 2
	SevError     SyslogSeverity = 3
	SevWarning   SyslogSeverity = 4
	SevNotice    SyslogSeverity = 5
	SevInfo      SyslogSeverity = 6
	SevDebug     SyslogSeverity = 7
)

// SyslogConfig holds syslog connection configuration.
type SyslogConfig struct {
	Server   string
	Port     int
	Protocol string         // "udp" or "tcp"
	Facility SyslogFacility // default Local4 (20)
	Tag      string         // APP-NAME, default "procSniper"
}

// SyslogClient implements a cross-platform RFC 5424 syslog sender.
type SyslogClient struct {
	config   SyslogConfig
	conn     net.Conn
	mu       sync.Mutex
	hostname string

	// TCP reconnect state
	connected     bool
	lastAttempt   time.Time
	backoff       time.Duration
	maxBackoff    time.Duration
	writeDeadline time.Duration
}

const (
	syslogInitialBackoff = 1 * time.Second
	syslogMaxBackoff     = 30 * time.Second
	syslogWriteDeadline  = 3 * time.Second
	syslogMaxUDPSize     = 2048
	syslogSDID           = "alert@49152"
)

// NewSyslogClient creates a new syslog client and attempts the initial connection.
// Returns a client even if the initial connection fails (will retry on send).
func NewSyslogClient(cfg SyslogConfig) (*SyslogClient, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("syslog server address is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 514
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "udp"
	}
	if cfg.Tag == "" {
		cfg.Tag = "procSniper"
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	c := &SyslogClient{
		config:        cfg,
		hostname:      hostname,
		backoff:       syslogInitialBackoff,
		maxBackoff:    syslogMaxBackoff,
		writeDeadline: syslogWriteDeadline,
	}

	if err := c.connect(); err != nil {
		log.Printf("[!] Syslog: initial connection to %s:%d (%s) failed: %v (will retry)",
			cfg.Server, cfg.Port, cfg.Protocol, err)
		return c, nil
	}

	return c, nil
}

func (c *SyslogClient) connect() error {
	addr := net.JoinHostPort(c.config.Server, fmt.Sprintf("%d", c.config.Port))

	var conn net.Conn
	var err error

	switch strings.ToLower(c.config.Protocol) {
	case "tcp":
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	default: // udp
		conn, err = net.Dial("udp", addr)
	}

	if err != nil {
		c.connected = false
		c.lastAttempt = time.Now()
		return err
	}

	c.conn = conn
	c.connected = true
	c.backoff = syslogInitialBackoff
	return nil
}

func (c *SyslogClient) reconnect() error {
	// Exponential backoff: skip if we reconnected too recently
	if time.Since(c.lastAttempt) < c.backoff {
		return fmt.Errorf("reconnect backoff: next attempt in %v", c.backoff-time.Since(c.lastAttempt))
	}

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	err := c.connect()
	if err != nil {
		// Increase backoff
		c.backoff *= 2
		if c.backoff > c.maxBackoff {
			c.backoff = c.maxBackoff
		}
		return err
	}
	return nil
}

// SendAlert formats a domain.Alert as an RFC 5424 syslog message and sends it.
func (c *SyslogClient) SendAlert(alert *domain.Alert) error {
	if alert == nil {
		return nil
	}

	severity := mapThreatToSyslogSeverity(alert.Severity)
	msg := c.formatRFC5424(severity, alert)

	return c.send(msg)
}

// Close closes the syslog connection.
func (c *SyslogClient) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.connected = false
}

func (c *SyslogClient) send(msg []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	isTCP := strings.ToLower(c.config.Protocol) == "tcp"

	// Reconnect if needed
	if !c.connected || c.conn == nil {
		if err := c.reconnect(); err != nil {
			return fmt.Errorf("syslog not connected: %w", err)
		}
	}

	// Set write deadline
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeDeadline)); err != nil {
		c.connected = false
		return fmt.Errorf("syslog set deadline: %w", err)
	}

	// For UDP, truncate if too large
	if !isTCP && len(msg) > syslogMaxUDPSize {
		msg = msg[:syslogMaxUDPSize]
	}

	// TCP messages are newline-delimited
	if isTCP {
		msg = append(msg, '\n')
	}

	_, err := c.conn.Write(msg)
	if err != nil {
		c.connected = false
		if isTCP {
			c.conn.Close()
			c.conn = nil
		}
		return fmt.Errorf("syslog write: %w", err)
	}

	return nil
}

func (c *SyslogClient) formatRFC5424(severity SyslogSeverity, alert *domain.Alert) []byte {
	// Priority = facility * 8 + severity
	pri := int(c.config.Facility)*8 + int(severity)

	// Timestamp in RFC 3339 with microsecond precision
	ts := alert.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z")

	// Structured data
	sd := fmt.Sprintf("[%s category=%s severity=%s score=%s pid=%s processGuid=%s image=%s indicatorCount=%s autoRespond=%s]",
		syslogSDID,
		sdParamValue(alert.Category),
		sdParamValue(string(alert.Severity)),
		sdParamValue(fmt.Sprintf("%d", alert.Score)),
		sdParamValue(fmt.Sprintf("%d", alert.ProcessID)),
		sdParamValue(alert.ProcessGuid),
		sdParamValue(alert.Image),
		sdParamValue(fmt.Sprintf("%d", len(alert.Indicators))),
		sdParamValue(fmt.Sprintf("%v", alert.AutoRespond)),
	)

	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	msg := fmt.Sprintf("<%d>1 %s %s %s %s - %s %s",
		pri,
		ts,
		c.hostname,
		c.config.Tag,
		alert.ID,
		sd,
		alert.Description,
	)

	return []byte(msg)
}

// sdParamValue escapes a value for RFC 5424 structured data.
// Per RFC 5424 Section 6.3.3: escape '"', '\', and ']'.
func sdParamValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `]`, `\]`)
	return `"` + s + `"`
}

// mapThreatToSyslogSeverity maps domain.ThreatLevel to RFC 5424 syslog severity.
func mapThreatToSyslogSeverity(level domain.ThreatLevel) SyslogSeverity {
	switch level {
	case domain.ThreatCritical:
		return SevCritical
	case domain.ThreatHigh:
		return SevError
	case domain.ThreatMedium:
		return SevWarning
	case domain.ThreatLow:
		return SevNotice
	default:
		return SevInfo
	}
}
