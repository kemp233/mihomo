package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	mihomonet "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	defaultMITMStreamLargeBodies = 8 * 1024 * 1024
	mitmHandshakeTimeout         = 30 * time.Second
	mitmListenerQueueSize        = 64
)

// MITMOption MITM outbound configuration.
type MITMOption struct {
	BasicOption
	Name              string `proxy:"name"`
	CADir             string `proxy:"ca-dir,omitempty"`
	RulesFile         string `proxy:"rules-file,omitempty"`
	StreamLargeBodies int64  `proxy:"stream-large-bodies,omitempty"`
	SSLInsecure       bool   `proxy:"ssl-insecure,omitempty"`
}

type MITM struct {
	*Base
	engine      *proxy.Proxy
	listener    *mitmListener
	rules       *mitmRuleSet
	caDir       string
	dialer      C.Dialer
	dialerProxy string
	tunnel      C.Tunnel
	closeOnce   sync.Once
}

// NewMITM creates a MITM interception outbound.
func NewMITM(option MITMOption) (*MITM, error) {
	if option.Name == "" {
		return nil, errors.New("mitm: name is empty")
	}
	if option.CADir == "" {
		return nil, errors.New("mitm: ca-dir is required")
	}
	if !filepath.IsAbs(option.CADir) {
		return nil, fmt.Errorf("mitm: ca-dir %q must be an absolute path", option.CADir)
	}
	if option.DialerProxy == option.Name {
		return nil, fmt.Errorf("mitm: dialer-proxy %q cannot reference itself", option.DialerProxy)
	}

	rules, err := loadMITMRuleSet(option.RulesFile)
	if err != nil {
		return nil, err
	}

	ca, err := getSharedCA(option.CADir)
	if err != nil {
		return nil, err
	}

	streamLarge := option.StreamLargeBodies
	if streamLarge <= 0 {
		streamLarge = defaultMITMStreamLargeBodies
	}

	b := NewBase(BaseOption{
		Name:         option.Name,
		Type:         C.MITM,
		ProviderName: option.ProviderName,
		UDP:          false,
		TFO:          option.TFO,
		MPTCP:        option.MPTCP,
		Interface:    option.Interface,
		RoutingMark:  option.RoutingMark,
		Prefer:       option.IPVersion,
	})

	m := &MITM{
		Base:        b,
		rules:       rules,
		caDir:       option.CADir,
		dialerProxy: option.DialerProxy,
		tunnel:      option.TunnelForAPI,
	}

	dialOpts := m.DialOptions()
	dialOpts = append(dialOpts, dialer.WithResolver(resolver.DirectHostResolver))
	if option.DialerProxy != "" {
		m.dialer = option.NewDialer(dialOpts)
	} else {
		m.dialer = dialer.NewDialer(dialOpts...)
	}

	opts := &proxy.Options{
		StreamLargeBodies:       streamLarge,
		NewCaFunc:               func() (cert.CA, error) { return ca, nil },
		DisableEnvironmentProxy: true,
		SslInsecure:             option.SSLInsecure,
	}
	opts.DialContext = m.dialUpstream

	engine, err := proxy.NewProxy(opts)
	if err != nil {
		return nil, err
	}
	engine.AddAddon(&mitmAddon{rules: rules})

	ln := newMITMListener()
	m.listener = ln
	m.engine = engine

	go func() {
		if err := engine.StartListener(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorln("MITM engine %s stopped: %v", option.Name, err)
		}
	}()

	return m, nil
}

// DialContext tunnels one TCP connection through the in-memory MITM engine.
func (m *MITM) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if metadata.NetWork == C.UDP {
		return nil, C.ErrNotSupport
	}
	if metadata.DstPort == 0 {
		return nil, errors.New("mitm: invalid destination port")
	}
	if err := m.checkDialerLoop(); err != nil {
		return nil, err
	}

	target := metadata.RemoteAddress()
	inner := metadata.Clone()
	inner.Type = C.INNER
	inner.SpecialProxy = ""
	inner.SpecialRules = ""
	inner.InName = ""
	inner.RematchName = ""
	inner.SniffHost = ""
	inner.NetWork = C.TCP

	client, server := mihomonet.Pipe()
	serverConn := &mitmServerConn{Conn: server, metadata: inner}

	handshake := mitmHandshakeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < handshake {
			handshake = remaining
		}
	}
	if err := client.SetDeadline(time.Now().Add(handshake)); err != nil {
		client.Close()
		server.Close()
		return nil, err
	}

	if err := m.listener.serve(ctx, serverConn); err != nil {
		client.Close()
		server.Close()
		return nil, err
	}

	if err := writeMITMConnectRequest(client, target); err != nil {
		client.Close()
		server.Close()
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
	}
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		client.Close()
		server.Close()
		return nil, fmt.Errorf("mitm: handshake with engine failed: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		client.Close()
		server.Close()
		return nil, fmt.Errorf("mitm: engine handshake returned status %d", resp.StatusCode)
	}

	if err := client.SetDeadline(time.Time{}); err != nil {
		client.Close()
		server.Close()
		return nil, err
	}

	return NewConn(mihomonet.WarpConnWithBioReader(client, br), m), nil
}

func writeMITMConnectRequest(client net.Conn, target string) error {
	_, err := io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	return err
}

func (m *MITM) dialUpstream(ctx context.Context, req *http.Request, network, address string) (net.Conn, error) {
	if err := m.checkDialerLoop(); err != nil {
		return nil, err
	}
	origin, _ := m.engine.OriginMetadata(req).(*C.Metadata)
	if origin == nil {
		return nil, fmt.Errorf("mitm: missing origin metadata for %s", address)
	}
	return m.dialer.DialContext(ctx, network, address)
}

func (m *MITM) checkDialerLoop() error {
	if m.dialerProxy == "" || m.tunnel == nil {
		return nil
	}
	t, ok := m.tunnel.(proxydialer.Tunnel)
	if !ok {
		return nil
	}
	p, exists := t.Proxies()[m.dialerProxy]
	if !exists {
		return fmt.Errorf("mitm: dialer-proxy %q not found", m.dialerProxy)
	}
	md := &C.Metadata{}
	for cur := p; cur != nil; cur = cur.Unwrap(md, false) {
		if cur.Type() == C.MITM {
			return fmt.Errorf("mitm: dialer-proxy %q resolves to MITM adapter, loop detected", m.dialerProxy)
		}
	}
	return nil
}

func (m *MITM) Close() error {
	m.closeOnce.Do(func() {
		m.listener.Close()
		if err := m.engine.Close(); err != nil {
			log.Debugln("MITM engine %s close: %v", m.Name(), err)
		}
		releaseSharedCA(m.caDir)
	})
	return nil
}

func (m *MITM) SupportUot() bool {
	return false
}

// mitmListener bridges in-memory pipe conns into the vendored engine.
type mitmListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newMITMListener() *mitmListener {
	return &mitmListener{
		conns: make(chan net.Conn, mitmListenerQueueSize),
		done:  make(chan struct{}),
	}
}

func (l *mitmListener) serve(ctx context.Context, c net.Conn) error {
	select {
	case l.conns <- c:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return errors.New("mitm engine closed")
	}
}

func (l *mitmListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, errors.New("mitm listener closed")
	}
}

func (l *mitmListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *mitmListener) Addr() net.Addr { return mitmAddr{} }

type mitmAddr struct{}

func (mitmAddr) Network() string { return "mitm" }
func (mitmAddr) String() string  { return "mitm-engine" }

// mitmServerConn carries the origin metadata into the engine.
type mitmServerConn struct {
	net.Conn
	metadata any
}

func (c *mitmServerConn) OriginMetadata() any { return c.metadata }
