package realip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

type module struct {
	next   httpserver.Handler
	From   []*net.IPNet
	Header string

	// MaxHops configures the maxiumum number of hops or IPs to be found in a forward header.
	// It's purpose is to prevent abuse and/or DOS attacks from long forward-chains, since each one
	// must be parsed and checked against a list of subnets.
	// The default is 5, -1 to disable. If set to 0, any request with a forward header will be rejected
	MaxHops int
	Strict  bool
}

func (m *module) validSource(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, from := range m.From {
		if from.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *module) ServeHTTP(w http.ResponseWriter, req *http.Request) (int, error) {
	host, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil || !m.validSource(host) {
		if m.Strict {
			return 403, fmt.Errorf("Error reading remote addr: %s", req.RemoteAddr)
		}
		return m.next.ServeHTTP(w, req) // Change nothing and let next deal with it.
	}
	if !m.validSource(host) {
		if m.Strict {
			return 403, fmt.Errorf("Unrecognized proxy ip address: %s", host)
		}
		return m.next.ServeHTTP(w, req)
	}

	if hVal := req.Header.Get(m.Header); hVal != "" {
		//restore original host:port format
		parts := strings.Split(hVal, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}
		if m.MaxHops != -1 && len(parts) > m.MaxHops {
			return 403, fmt.Errorf("Too many forward addresses")
		}
		ip := net.ParseIP(parts[len(parts)-1])
		if ip == nil {
			if m.Strict {
				return 403, fmt.Errorf("Unrecognized proxy ip address: %s", parts[len(parts)-1])
			}
			return m.next.ServeHTTP(w, req)
		}
		req.RemoteAddr = net.JoinHostPort(parts[len(parts)-1], port)
		for i := len(parts) - 1; i >= 0; i-- {
			req.RemoteAddr = net.JoinHostPort(parts[i], port)
			if i > 0 && !m.validSource(parts[i]) {
				if m.Strict {
					return 403, fmt.Errorf("Unrecognized proxy ip address: %s", parts[i])
				}
				return m.next.ServeHTTP(w, req)
			}
		}
	}
	return m.next.ServeHTTP(w, req)
}
