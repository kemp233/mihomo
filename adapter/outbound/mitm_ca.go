package outbound

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/lqqyt2423/go-mitmproxy/cert"
)

// Shared CA instances keyed by cleaned ca-dir, so MITM outbounds using the
// same ca-dir (e.g. MITM-DIRECT / MITM-PROXY) reuse one root certificate.
var (
	mitmCaMu    sync.Mutex
	mitmCaCache = map[string]*mitmSharedCA{}
)

type mitmSharedCA struct {
	ca  cert.CA
	ref int
}

func getSharedCA(dir string) (cert.CA, error) {
	key := filepath.Clean(dir)
	mitmCaMu.Lock()
	defer mitmCaMu.Unlock()
	if s, ok := mitmCaCache[key]; ok {
		s.ref++
		return s.ca, nil
	}
	ca, err := cert.NewSelfSignCA(dir)
	if err != nil {
		return nil, fmt.Errorf("mitm: load/create CA in %s: %w", dir, err)
	}
	root := ca.GetRootCA()
	if root == nil || !root.IsCA || !root.BasicConstraintsValid || time.Now().After(root.NotAfter) {
		return nil, fmt.Errorf("mitm: invalid CA certificate in %s", dir)
	}
	mitmCaCache[key] = &mitmSharedCA{ca: ca, ref: 1}
	return ca, nil
}

func releaseSharedCA(dir string) {
	key := filepath.Clean(dir)
	mitmCaMu.Lock()
	defer mitmCaMu.Unlock()
	if s, ok := mitmCaCache[key]; ok {
		s.ref--
		if s.ref <= 0 {
			delete(mitmCaCache, key)
		}
	}
}
