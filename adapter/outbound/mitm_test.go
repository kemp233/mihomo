package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const testAdHTML = `<html><body><div id="content">hello-content</div><div class="ad">AD-BLOCK-ME</div></body></html>`

func newTestMITM(t *testing.T, rulesYAML string) (*MITM, string) {
	t.Helper()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, testAdHTML)
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	rulesPath := ""
	if rulesYAML != "" {
		rulesPath = filepath.Join(dir, "rules.yaml")
		if err := os.WriteFile(rulesPath, []byte(rulesYAML), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	m, err := NewMITM(MITMOption{
		Name:      "TEST-MITM",
		CADir:     filepath.Join(dir, "ca"),
		RulesFile: rulesPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m, upstream.URL
}

func mitmMetadata(t *testing.T, serverURL string) *C.Metadata {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(serverURL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return &C.Metadata{
		NetWork: C.TCP,
		Type:    C.HTTP,
		Host:    host,
		DstIP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		DstPort: port,
		SrcIP:   netip.AddrFrom4([4]byte{127, 0, 0, 1}),
		SrcPort: 12345,
	}
}

func mitmRequest(t *testing.T, m *MITM, serverURL, rawReq string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := m.DialContext(ctx, mitmMetadata(t, serverURL))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 64*1024)
	n := 0
	for {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil || n >= len(buf) {
			break
		}
	}
	return buf[:n]
}

func TestMITMSelectorFiltering(t *testing.T) {
	rules := `
version: 1
response-body-rules:
  - hosts: ["127.0.0.1"]
    content-type: "text/html"
    selectors: [".ad"]
`
	m, url := newTestMITM(t, rules)
	raw := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	resp := mitmRequest(t, m, url, raw)

	s := string(resp)
	if want := "hello-content"; !contains(s, want) {
		t.Fatalf("expected body to contain %q, got:\n%s", want, s)
	}
	if want := "AD-BLOCK-ME"; contains(s, want) {
		t.Fatalf("expected ad element removed, got:\n%s", s)
	}
}

func TestMITMTextReplace(t *testing.T) {
	rules := `
version: 1
response-text-rules:
  - hosts: ["127.0.0.1"]
    content-type: "text/html"
    pattern: "AD-BLOCK-ME"
    replace: "REPLACED"
`
	m, url := newTestMITM(t, rules)
	raw := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	resp := mitmRequest(t, m, url, raw)

	s := string(resp)
	if !contains(s, "REPLACED") {
		t.Fatalf("expected replaced text, got:\n%s", s)
	}
	if contains(s, "AD-BLOCK-ME") {
		t.Fatalf("expected original text removed, got:\n%s", s)
	}
}

func TestMITMPassThroughAndBlockedHost(t *testing.T) {
	rules := `
version: 1
request-host-rules: ["blocked.example.com"]
`
	m, url := newTestMITM(t, rules)
	raw := "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
	resp := mitmRequest(t, m, url, raw)
	if !contains(string(resp), "hello-content") {
		t.Fatalf("expected pass-through for non-blocked host, got:\n%s", string(resp))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	md := mitmMetadata(t, url)
	md.Host = "blocked.example.com"
	conn, err := m.DialContext(ctx, md)
	if err != nil {
		t.Fatalf("DialContext blocked host: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	n := 0
	for {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil || n >= len(buf) {
			break
		}
	}
	if !contains(string(buf[:n]), "403") {
		t.Fatalf("expected 403 for blocked host, got:\n%s", string(buf[:n]))
	}
}

func TestMITMSharedCA(t *testing.T) {
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	for i := 0; i < 2; i++ {
		m, err := NewMITM(MITMOption{
			Name:  fmt.Sprintf("MITM-%d", i),
			CADir: caDir,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = m.Close() })
	}
	if _, err := os.Stat(filepath.Join(caDir, "mitmproxy-ca-cert.pem")); err != nil {
		t.Fatalf("CA cert not written: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
