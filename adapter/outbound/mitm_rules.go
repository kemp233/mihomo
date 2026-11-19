package outbound

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/cascadia"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
	"golang.org/x/net/html"
)

const mitmRulesMaxSize = 16 * 1024 * 1024

type mitmRuleFile struct {
	Version           int                 `yaml:"version,omitempty"`
	RequestHostRules  []string            `yaml:"request-host-rules,omitempty"`
	ResponseBodyRules []*mitmBodyRuleSpec `yaml:"response-body-rules,omitempty"`
	ResponseTextRules []*mitmTextRuleSpec `yaml:"response-text-rules,omitempty"`
}

type mitmBodyRuleSpec struct {
	Hosts       []string `yaml:"hosts,omitempty"`
	ContentType string   `yaml:"content-type,omitempty"`
	Selectors   []string `yaml:"selectors"`
}

type mitmTextRuleSpec struct {
	Hosts       []string `yaml:"hosts,omitempty"`
	ContentType string   `yaml:"content-type,omitempty"`
	Pattern     string   `yaml:"pattern"`
	Replace     string   `yaml:"replace,omitempty"`
}

type compiledBodyRule struct {
	hosts    []string
	content  string
	selector cascadia.Selector
}

type compiledTextRule struct {
	hosts   []string
	content string
	re      *regexp.Regexp
	replace []byte
}

type mitmRuleSet struct {
	requestHosts []string
	bodyRules    []compiledBodyRule
	textRules    []compiledTextRule
}

func loadMITMRuleSet(path string) (*mitmRuleSet, error) {
	rs := &mitmRuleSet{}
	if path == "" {
		return rs, nil
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("mitm: rules-file %q must be an absolute path", path)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mitm: open rules-file: %w", err)
	}
	defer fh.Close()

	data, err := io.ReadAll(io.LimitReader(fh, mitmRulesMaxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > mitmRulesMaxSize {
		return nil, fmt.Errorf("mitm: rules file exceeds %d bytes", mitmRulesMaxSize)
	}

	var spec mitmRuleFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&spec); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("mitm: parse rules-file: %w", err)
	}

	for _, h := range spec.RequestHostRules {
		if h == "" {
			return nil, errors.New("mitm: empty host in request-host-rules")
		}
		rs.requestHosts = append(rs.requestHosts, strings.ToLower(strings.TrimSuffix(h, ".")))
	}

	for i, s := range spec.ResponseBodyRules {
		if len(s.Selectors) == 0 {
			return nil, fmt.Errorf("mitm: response-body-rules[%d] requires selectors", i)
		}
		combined := strings.Join(s.Selectors, ",")
		sel, err := cascadia.Compile(combined)
		if err != nil {
			return nil, fmt.Errorf("mitm: response-body-rules[%d] invalid selector: %w", i, err)
		}
		contentType := s.ContentType
		if contentType == "" {
			contentType = "text/html"
		}
		rs.bodyRules = append(rs.bodyRules, compiledBodyRule{
			hosts:    lowerMITMHosts(s.Hosts),
			content:  contentType,
			selector: sel,
		})
	}

	for i, s := range spec.ResponseTextRules {
		if s.Pattern == "" {
			return nil, fmt.Errorf("mitm: response-text-rules[%d] requires pattern", i)
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return nil, fmt.Errorf("mitm: response-text-rules[%d] invalid pattern: %w", i, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("mitm: response-text-rules[%d] pattern matches empty string", i)
		}
		if s.ContentType == "" {
			return nil, fmt.Errorf("mitm: response-text-rules[%d] requires content-type", i)
		}
		rs.textRules = append(rs.textRules, compiledTextRule{
			hosts:   lowerMITMHosts(s.Hosts),
			content: s.ContentType,
			re:      re,
			replace: []byte(s.Replace),
		})
	}

	return rs, nil
}

func lowerMITMHosts(hosts []string) []string {
	if len(hosts) == 0 {
		return nil
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h == "" {
			continue
		}
		out = append(out, strings.ToLower(strings.TrimSuffix(h, ".")))
	}
	return out
}

func matchMITMHost(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func matchMITMContentType(headerValue, want string) bool {
	media, _, err := mime.ParseMediaType(headerValue)
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(media), strings.TrimSpace(want))
}

func (rs *mitmRuleSet) blockRequest(host string) bool {
	if len(rs.requestHosts) == 0 {
		return false
	}
	return matchMITMHost(strings.ToLower(host), rs.requestHosts)
}

func (rs *mitmRuleSet) matchBodyRules(host string, resp *proxy.Response) []compiledBodyRule {
	var out []compiledBodyRule
	for _, r := range rs.bodyRules {
		if len(r.hosts) > 0 && !matchMITMHost(host, r.hosts) {
			continue
		}
		if !matchMITMContentType(resp.Header.Get("Content-Type"), r.content) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (rs *mitmRuleSet) matchTextRules(host string, resp *proxy.Response) []compiledTextRule {
	var out []compiledTextRule
	for _, r := range rs.textRules {
		if len(r.hosts) > 0 && !matchMITMHost(host, r.hosts) {
			continue
		}
		if !matchMITMContentType(resp.Header.Get("Content-Type"), r.content) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// applyResponse filters a buffered response. It never touches streaming flows.
func (rs *mitmRuleSet) applyResponse(f *proxy.Flow) {
	if f.Request == nil || f.Response == nil {
		return
	}
	if f.Stream {
		return
	}
	if f.Response.StatusCode < 200 || f.Response.StatusCode >= 300 {
		return
	}
	host := strings.ToLower(f.Request.URL.Hostname())

	bodyRules := rs.matchBodyRules(host, f.Response)
	textRules := rs.matchTextRules(host, f.Response)
	if len(bodyRules) == 0 && len(textRules) == 0 {
		return
	}

	body, err := f.Response.DecodedBody()
	if err != nil {
		log.Debugln("[MITM] decode body for %s failed: %v", host, err)
		return
	}
	if len(body) == 0 {
		return
	}
	if !utf8.Valid(body) {
		log.Debugln("[MITM] skip non-utf8 body for %s", host)
		return
	}

	modified := false
	if len(bodyRules) > 0 {
		if nb, ok := applyHTMLSelectors(body, bodyRules); ok {
			body = nb
			modified = true
		}
	}
	if len(textRules) > 0 {
		nb := body
		for _, r := range textRules {
			nb = r.re.ReplaceAll(nb, r.replace)
		}
		if !bytes.Equal(nb, body) {
			body = nb
			modified = true
		}
	}
	if !modified {
		return
	}

	f.Response.Body = body
	f.Response.Header.Del("Content-Encoding")
	f.Response.Header.Del("Transfer-Encoding")
	f.Response.Header.Del("ETag")
	f.Response.Header.Del("Content-MD5")
	f.Response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	log.Debugln("[MITM] filtered response body for %s", host)
}

func applyHTMLSelectors(body []byte, rules []compiledBodyRule) ([]byte, bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	modified := false
	for _, rule := range rules {
		for _, node := range cascadia.QueryAll(doc, rule.selector) {
			if node.Parent != nil {
				node.Parent.RemoveChild(node)
				modified = true
			}
		}
	}
	if !modified {
		return nil, false
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// mitmAddon applies rules inside the vendored engine.
type mitmAddon struct {
	proxy.BaseAddon
	rules *mitmRuleSet
}

func (a *mitmAddon) Requestheaders(f *proxy.Flow) {
	if f.Request == nil || a.rules == nil {
		return
	}
	if f.Request.Method == http.MethodConnect {
		return
	}
	if a.rules.blockRequest(f.Request.URL.Hostname()) {
		log.Infoln("[MITM] blocked request %s %s", f.Request.Method, f.Request.URL.String())
		header := http.Header{}
		header.Set("Content-Type", "text/plain; charset=utf-8")
		f.Response = &proxy.Response{
			StatusCode: http.StatusForbidden,
			Header:     header,
			Body:       []byte("blocked by mihomo mitm rules\n"),
		}
	}
}

func (a *mitmAddon) Response(f *proxy.Flow) {
	if f.Response == nil || f.Request == nil || a.rules == nil {
		return
	}
	a.rules.applyResponse(f)
}
