package realip

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestRealIP(t *testing.T) {
	for i, test := range []struct {
		actualIP   string
		headerVal  string
		expectedIP string
	}{
		{"1.2.3.4:123", "", "1.2.3.4:123"},
		{"4.4.255.255:123", "", "4.4.255.255:123"},
		{"4.5.0.0:123", "1.2.3.4", "1.2.3.4:123"},

		// because 111.111.111.111 is NOT in a trusted subnet, the next in the chain should not be trusted
		{"4.5.2.3:123", "1.2.6.7,5.6.7.8,111.111.111.111", "111.111.111.111:123"},
		{"4.5.5.5:123", "NOTANIP", "4.5.5.5:123"},
		{"aaaaaa", "1.2.3.4", "aaaaaa"},
		{"aaaaaa:123", "1.2.3.4", "aaaaaa:123"},

		{"4.5.2.3:123", "1.2.6.7,5.6.7.8,4.5.6.7", "5.6.7.8:123"},

		// expectedIP is empty because the server should have returned a 403
		// since the chain is longer than the configured max (5)
		{"4.5.2.3:123", "1.2.6.7,5.6.7.8,4.5.6.7,5.6.7.8,4.5.6.7,1.2.3.4", ""},
	} {
		remoteAddr := ""
		_, ipnet, err := net.ParseCIDR("4.5.0.0/16") // "4.5.x.x"
		if err != nil {
			t.Fatal(err)
		}

		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			remoteAddr = r.RemoteAddr
			return nil
		})

		he := &RealIP{
			Header:  "X-Real-IP",
			MaxHops: 5,
			From:    []*net.IPNet{ipnet},
			logger:  zap.NewExample(),
		}
		err = he.buildCompleteSet(false)
		if err != nil {
			t.Fatal(err)
		}

		req, err := http.NewRequest("GET", "http://foo.tld/", nil)
		if err != nil {
			t.Fatalf("Test %d: Could not create HTTP request: %v", i, err)
		}
		req.RemoteAddr = test.actualIP
		if test.headerVal != "" {
			req.Header.Set("X-Real-IP", test.headerVal)
		}

		rec := httptest.NewRecorder()
		he.ServeHTTP(rec, req, next)

		if remoteAddr != test.expectedIP {
			t.Errorf("Test %d: Expected '%s', but found '%s'", i, test.expectedIP, remoteAddr)
		}
	}
}

func TestCidrAndPresets(t *testing.T) {
	tests := []struct {
		rule     string
		presets  []string
		expected []string
	}{
		{"cloudflare", []string{"cloudflare"}, nil},
		{"1.2.3.4/32 5.6.7.8/32", nil, []string{"1.2.3.4/32", "5.6.7.8/32"}},
		{"1.2.3.4/32 \n from 5.6.7.8/32", nil, []string{"1.2.3.4/32", "5.6.7.8/32"}}, // run over multiple lines
	}
	for i, test := range tests {

		input := fmt.Sprintf(`realip {
			header "X-Forwarded-For"
			from %s
			maxhops 5
		}`, test.rule)

		d := caddyfile.NewTestDispenser(input)
		m := &RealIP{
			logger: zap.NewExample(),
		}

		err := m.UnmarshalCaddyfile(d)
		if err != nil {
			t.Fatalf("Test %d: failed while parsing: '%s'; got '%v'", i, test.rule, err)
		}

		m.buildCompleteSet(false)

		var cidrs []*net.IPNet
		for _, name := range test.presets {
			if preset, ok := presetRegistry[name]; ok {
				cidrs = append(cidrs, preset.Ranges...)
			} else {
				t.Fatalf("Test %d: Specified preset missing: %s", i, name)
			}
		}
		result, err := parseCidrs(i, test.expected)
		if err != nil {
			t.Fatal(err)
		}

		cidrs = append(cidrs, result...)
		for _, cidr := range cidrs {
			found := false
			for _, from := range m.complete {
				if net.IP.Equal(from.IP, cidr.IP) && bytes.Equal(from.Mask, cidr.Mask) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Test %d: Expected %q, but missing from result: %q", i, cidr, m.From)
			}
		}
	}
}

func parseCidrs(i int, values []string) ([]*net.IPNet, error) {
	var cidrs []*net.IPNet
	for _, value := range values {
		_, cidr, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("Test %d: Failed to parse CIDR %q, got: %v", i, value, err)
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs, nil
}

func TestJson(t *testing.T) {
	tester := caddytest.NewTester(t)

	cfg := `{
		"apps": {
			"http": {
				"servers": {
					"srv0": {
						"listen": [
							":8080"
						],
						"routes": [
							{
								"handle": [
									{
										"handler": "realip",
										"presets": ["cloudfront"],
										"from": [{"IP":"127.0.0.1","Mask":"////AA=="}],
										"header": "X-Forwarded-For",
										"strict": true
									},
									{
										"handler": "static_response",
										"status_code": 200,
										"body": "Hello from {http.request.remote}"
									}
								]
							}
						]
					}
				}
			}
		}
	}
	`

	tester.InitServer(cfg, "json")

	req, err := http.NewRequest("GET", "http://geo.caddy.localhost:8080", nil)
	if err != nil {
		t.Fatalf("unable to create request %s", err)
	}

	tests := []struct {
		xForwardedFor string
		expected      string
	}{
		{
			// trust localhost (testing infrastructure forces the use of 127.0.0.1)
			"202.36.75.151,127.0.0.1",
			"202.36.75.151",
		},
		{
			// trust cloudfront intermediate
			"202.36.75.151,188.114.96.1,127.0.0.1",
			"202.36.75.151",
		},
	}
	for i, test := range tests {
		req.Header.Add("X-Forwarded-For", test.xForwardedFor)
		resp := tester.AssertResponseCode(req, 200)
		data, _ := ioutil.ReadAll(resp.Body)
		if !strings.Contains(string(data), test.expected) {
			t.Logf("test %d expected: %s got: %s", i, test.expected, string(data))
			t.Fail()
		}
	}
}
