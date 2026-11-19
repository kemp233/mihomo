# Vendored go-mitmproxy

Source: https://github.com/lqqyt2423/go-mitmproxy
Version: v1.9.5
Commit: 07e0ca55ae1739a936147ac9878de0fa25f53a90

Only the proxy, certificate and internal packages are included. The original
MIT license in LICENSE applies to these files.

Local integration changes:

- Support a caller-provided net.Conn dialer and disable environment proxies.
- Serve an existing listener and retain per-connection origin metadata.
- Use private CA directory and key permissions.

The module dependency versions follow the parent Mihomo module.
