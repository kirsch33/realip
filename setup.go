package realip

import (
	"net"
	"strconv"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("realip", caddy.Plugin{
		ServerType: "http",
		Action:     Setup,
	})
}

func Setup(c *caddy.Controller) error {
	var m *module
	for c.Next() {
		if m != nil {
			return c.Err("cannot specify realip more than once")
		}
		m = &module{
			Header:  "X-Forwarded-For",
			MaxHops: 5,
		}
		if err := parse(m, c); err != nil {
			return err
		}
	}
	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		m.next = next
		return m
	})
	return nil
}

func parse(m *module, c *caddy.Controller) (err error) {
	args := c.RemainingArgs()
	if len(args) > 0 {
		if err := addIpRanges(m, c, args); err != nil {
			return err
		}
	}
	for c.NextBlock() {
		var err error
		switch c.Val() {
		case "header":
			m.Header, err = StringArg(c)
		case "from":
			err = addIpRanges(m, c, c.RemainingArgs())
		case "strict":
			m.Strict, err = BoolArg(c)
		case "maxhops":
			m.MaxHops, err = IntArg(c)
		default:
			return c.Errf("Unknown realip arg: %s", c.Val())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Adds a list of CIDR IP Ranges to the From whitelist
func addIpRanges(m *module, c *caddy.Controller, ranges []string) error {
	for _, v := range ranges {
		if preset, ok := presets[v]; ok {
			if err := addIpRanges(m, c, preset); err != nil {
				return err
			}
			continue
		}
		_, cidr, err := net.ParseCIDR(v)
		if err != nil {
			return c.Err(err.Error())
		}
		m.From = append(m.From, cidr)
	}
	return nil
}

//
// Helpers below here could potentially be methods on *caddy.Controller for convenience
//

// IntArg check's there is only one arg, parses, and returns it
func IntArg(c *caddy.Controller) (int, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return 0, c.ArgErr()
	}
	return strconv.Atoi(args[0])
}

// Assert only one arg and return it
func StringArg(c *caddy.Controller) (string, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return "", c.ArgErr()
	}
	return args[0], nil
}

// Assert only one arg is a valid cidr notation
func CidrArg(c *caddy.Controller) (*net.IPNet, error) {
	a, err := StringArg(c)
	if err != nil {
		return nil, err
	}
	_, cidr, err := net.ParseCIDR(a)
	if err != nil {
		return nil, err
	}
	return cidr, nil
}

func BoolArg(c *caddy.Controller) (bool, error) {
	args := c.RemainingArgs()
	if len(args) > 1 {
		return false, c.ArgErr()
	}
	if len(args) == 0 {
		return true, nil
	}
	switch args[0] {
	case "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, c.Errf("Unexpected bool value: %s", args[0])
	}
}

func NoArgs(c *caddy.Controller) error {
	if len(c.RemainingArgs()) != 0 {
		return c.ArgErr()
	}
	return nil
}
