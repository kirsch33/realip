package realip

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type RealIP struct {

	// Presets stores the presets that should be loaded
	Presets []string `json:"presets"`

	// From stores any manually included presets
	From []*net.IPNet `json:"from"`

	// Header to load an IP Address from typically X-Forwarded-For
	Header string `json:"header"`

	// MaxHops configures the maxiumum number of hops or IPs to be found in a forward header.
	// It's purpose is to prevent abuse and/or DOS attacks from long forward-chains, since each one
	// must be parsed and checked against a list of subnets.
	// The default is 5, -1 to disable. If set to 0, any request with a forward header will be rejected
	MaxHops int `json:"max_hops"`

	// Will reject the request if a valid IP address can not be found
	Strict bool `json:"strict"`

	// How often the dynamic presets are reloaded
	RefreshFrequency caddy.Duration `json:"refresh_frequency"`

	done     chan bool
	logger   *zap.Logger
	complete []*net.IPNet
}

type CIDRUpdater func() ([]*net.IPNet, error)

type CIDRSet struct {
	Ranges []*net.IPNet
	Update CIDRUpdater
}

func init() {
	caddy.RegisterModule(RealIP{})
	httpcaddyfile.RegisterHandlerDirective("realip", parseCaddyfileHandler)
}

func (RealIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.realip",
		New: func() caddy.Module {
			return new(RealIP)
		},
	}
}

func (m *RealIP) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	if m.RefreshFrequency == 0 {
		m.RefreshFrequency = caddy.Duration(24 * time.Hour)
	}

	if m.MaxHops == 0 {
		m.MaxHops = 5
	}

	m.done = make(chan bool, 1)

	go func() {
		ticker := time.NewTicker(time.Duration(m.RefreshFrequency))
		defer ticker.Stop()

		m.buildCompleteSet(true)

		for {
			select {
			case <-ticker.C:
				err := m.buildCompleteSet(true)
				if err != nil {
					m.logger.Error("downloading database failed", zap.Error(err))
				}
			case <-m.done:
				m.logger.Info("downloading stopped")
				return
			}
		}
	}()

	return m.buildCompleteSet(false)
}

func (m *RealIP) Cleanup() error {

	// stop all background tasks
	if m.done != nil {
		close(m.done)
	}

	return nil
}

func (m *RealIP) buildCompleteSet(updateDynamicPresets bool) error {

	if updateDynamicPresets {
		// refresh presets
		for name, p := range presetRegistry {
			if p.Update != nil {
				m.logger.Info("refreshing dynamic preset", zap.String("name", name))
				newRanges, err := p.Update()

				if err != nil {
					m.logger.Error("failed to update dynamic preset", zap.String("name", name), zap.Error(err))
				} else {
					p.Ranges = newRanges
					m.logger.Info("updated ranges", zap.String("name", name), zap.Int("count", len(newRanges)))
				}
			}
		}
	}

	set := make([]*net.IPNet, 0)

	// append any manual entries
	set = append(set, m.From...)

	// append current preset ranges
	for _, p := range m.Presets {
		set = append(set, presetRegistry[p].Ranges...)
	}

	m.complete = set
	return nil
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m RealIP
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, err
}

func addIpRanges(m *RealIP, d *caddyfile.Dispenser, ranges []string) error {
	for _, v := range ranges {
		if _, ok := presetRegistry[v]; ok {
			m.Presets = append(m.Presets, v)
			continue
		}
		_, cidr, err := net.ParseCIDR(v)
		if err != nil {
			return d.Err(err.Error())
		}
		m.From = append(m.From, cidr)
	}
	return nil
}

func parseStringArg(d *caddyfile.Dispenser, out *string) error {
	if !d.Args(out) {
		return d.ArgErr()
	}
	return nil
}

func parseIntArg(d *caddyfile.Dispenser, out *int) error {
	var strVal string
	err := parseStringArg(d, &strVal)
	if err == nil {
		*out, err = strconv.Atoi(strVal)
	}
	return err
}

func parseBoolArg(d *caddyfile.Dispenser, out *bool) error {
	var strVal string
	err := parseStringArg(d, &strVal)
	if err == nil {
		*out, err = strconv.ParseBool(strVal)
	}
	return err
}

func (m *RealIP) validSource(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, from := range m.complete {
		if from.Contains(ip) {
			return true
		}
	}
	return false
}

func (m RealIP) ServeHTTP(w http.ResponseWriter, req *http.Request, handler caddyhttp.Handler) error {

	m.logger.Info("checking the header",
		zap.String("header", m.Header),
		zap.String("remoteaddr", req.RemoteAddr),
		zap.Int("maxhops", m.MaxHops),
	)

	// check the direct upstream server
	host, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil || !m.validSource(host) {
		if m.Strict {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		return handler.ServeHTTP(w, req)
	}
	if !m.validSource(host) {
		if m.Strict {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		return handler.ServeHTTP(w, req)
	}

	// check the forwarded for header
	if hVal := req.Header.Get(m.Header); hVal != "" {
		parts := strings.Split(hVal, ",")
		for i, part := range parts {
			parts[i] = strings.TrimSpace(part)
		}

		if m.MaxHops != -1 && len(parts) > m.MaxHops {
			return caddyhttp.Error(http.StatusForbidden, err)
		}
		ip := net.ParseIP(parts[len(parts)-1])

		if ip == nil {
			if m.Strict {
				return caddyhttp.Error(http.StatusForbidden, err)
			}
			return handler.ServeHTTP(w, req)
		}
		req.RemoteAddr = net.JoinHostPort(parts[len(parts)-1], port)

		for i := len(parts) - 1; i >= 0; i-- {
			req.RemoteAddr = net.JoinHostPort(parts[i], port)
			if i > 0 && !m.validSource(parts[i]) {
				if m.Strict {
					return caddyhttp.Error(http.StatusForbidden, err)
				}

				return handler.ServeHTTP(w, req)
			}
		}
	}
	return handler.ServeHTTP(w, req)
}

func (m *RealIP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.NextArg()

	for d.NextBlock(0) {
		var err error

		switch d.Val() {
		case "header":
			err = parseStringArg(d, &m.Header)
		case "from":
			err = addIpRanges(m, d, d.RemainingArgs())
		case "strict":
			err = parseBoolArg(d, &m.Strict)
		case "maxhops":
			err = parseIntArg(d, &m.MaxHops)
		default:
			return d.Errf("Unknown realip arg")
		}
		if err != nil {
			return d.Errf("Error parsing %s: %s", d.Val(), err)
		}
	}
	return nil
}

func MustParseCIDR(cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return ipnet
}

var (
	_ caddyhttp.MiddlewareHandler = (*RealIP)(nil)
	_ caddy.Provisioner           = (*RealIP)(nil)
	_ caddyfile.Unmarshaler       = (*RealIP)(nil)
	_ caddy.CleanerUpper          = (*RealIP)(nil)
)
