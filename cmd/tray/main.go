//go:build windows

// Command tray is the procSniper operator system-tray helper. It runs in the operator's interactive
// session (NOT the Session-0 service) and talks to the agent's local HTTP API: show protection
// status, start/stop protection, and open the browser console (with the bearer token injected).
//
// The agent (service) writes its bearer token to `api_token` next to its exe; the tray reads it
// (default: api_token next to the tray exe, assuming co-located install) to authenticate.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/systray"
)

var (
	apiAddr string
	token   string
)

func main() {
	flag.StringVar(&apiAddr, "addr", "127.0.0.1:8787", "agent API address (loopback)")
	tokenFile := flag.String("token-file", "", "path to the API bearer-token file (default: api_token next to this exe)")
	flag.Parse()
	token = readToken(*tokenFile)
	systray.Run(onReady, func() {})
}

func readToken(path string) string {
	if path == "" {
		if exe, err := os.Executable(); err == nil {
			path = filepath.Join(filepath.Dir(exe), "api_token")
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func onReady() {
	systray.SetIcon(trayIcon())
	systray.SetTitle("procSniper")
	systray.SetTooltip("procSniper agent")

	mStatus := systray.AddMenuItem("Status: …", "Protection status")
	mStatus.Disable()
	systray.AddSeparator()
	mStart := systray.AddMenuItem("Start Protection", "Start real-time protection")
	mStop := systray.AddMenuItem("Stop Protection", "Stop real-time protection")
	systray.AddSeparator()
	mConsole := systray.AddMenuItem("Open Console", "Open the browser console")
	mQuit := systray.AddMenuItem("Quit Tray", "Quit this tray helper (does NOT stop the service)")

	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		refresh := func() {
			protecting, ok := apiStatus()
			switch {
			case !ok:
				mStatus.SetTitle("Status: agent unreachable")
				systray.SetTooltip("procSniper: agent unreachable")
			case protecting:
				mStatus.SetTitle("Status: Protected")
				systray.SetTooltip("procSniper: protected")
			default:
				mStatus.SetTitle("Status: Stopped")
				systray.SetTooltip("procSniper: stopped")
			}
		}
		refresh()
		for range t.C {
			refresh()
		}
	}()

	for {
		select {
		case <-mStart.ClickedCh:
			apiPost("/api/protect/start")
		case <-mStop.ClickedCh:
			apiPost("/api/protect/stop")
		case <-mConsole.ClickedCh:
			openBrowser(fmt.Sprintf("http://%s/#token=%s", apiAddr, token))
		case <-mQuit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

func httpClient() *http.Client { return &http.Client{Timeout: 5 * time.Second} }

// apiStatus returns (protecting, reachable).
func apiStatus() (bool, bool) {
	req, err := http.NewRequest(http.MethodGet, "http://"+apiAddr+"/api/protect/status", nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient().Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var s struct {
		Protecting bool `json:"protecting"`
	}
	_ = json.Unmarshal(b, &s)
	return s.Protecting, true
}

func apiPost(path string) {
	req, err := http.NewRequest(http.MethodPost, "http://"+apiAddr+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if resp, err := httpClient().Do(req); err == nil {
		resp.Body.Close()
	}
}

// openBrowser opens url in the default browser (Windows). FileProtocolHandler handles the
// #token=... fragment without the quoting pitfalls of `cmd /c start`.
func openBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// trayIcon builds a minimal solid 16x16 32bpp .ico in code (Windows tray needs ICO bytes), so the
// helper needs no external icon asset.
func trayIcon() []byte {
	const w, h = 16, 16
	buf := new(bytes.Buffer)
	le := binary.LittleEndian
	// ICONDIR
	_ = binary.Write(buf, le, uint16(0)) // reserved
	_ = binary.Write(buf, le, uint16(1)) // type: icon
	_ = binary.Write(buf, le, uint16(1)) // count
	// ICONDIRENTRY
	buf.WriteByte(w)
	buf.WriteByte(h)
	buf.WriteByte(0) // color count
	buf.WriteByte(0) // reserved
	_ = binary.Write(buf, le, uint16(1))  // planes
	_ = binary.Write(buf, le, uint16(32)) // bit count
	andRow := (w + 31) / 32 * 4
	dibSize := 40 + w*h*4 + h*andRow
	_ = binary.Write(buf, le, uint32(dibSize))
	_ = binary.Write(buf, le, uint32(22)) // image offset
	// BITMAPINFOHEADER
	_ = binary.Write(buf, le, uint32(40))  // biSize
	_ = binary.Write(buf, le, int32(w))    // biWidth
	_ = binary.Write(buf, le, int32(h*2))  // biHeight (XOR + AND)
	_ = binary.Write(buf, le, uint16(1))   // planes
	_ = binary.Write(buf, le, uint16(32))  // bit count
	_ = binary.Write(buf, le, uint32(0))   // compression
	_ = binary.Write(buf, le, uint32(0))   // size image
	_ = binary.Write(buf, le, int32(0))    // x ppm
	_ = binary.Write(buf, le, int32(0))    // y ppm
	_ = binary.Write(buf, le, uint32(0))   // colors used
	_ = binary.Write(buf, le, uint32(0))   // colors important
	// XOR pixels (bottom-up), BGRA — solid procSniper blue, opaque.
	for i := 0; i < w*h; i++ {
		buf.WriteByte(0xE0) // B
		buf.WriteByte(0x60) // G
		buf.WriteByte(0x10) // R
		buf.WriteByte(0xFF) // A
	}
	// AND mask: all opaque (zero), rows padded to 32 bits.
	for i := 0; i < h*andRow; i++ {
		buf.WriteByte(0)
	}
	return buf.Bytes()
}
