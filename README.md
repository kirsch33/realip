# realip for Caddy v2

This repo is a port of captncraig's "realip" module to Caddy v2. See original plugin below:

https://github.com/captncraig/caddy-realip

## Syntax
```Caddyfile

# tell caddy to process realip before other plugins
order realip first

realip {
    header name
    from cidr
    maxhops #
    strict
}
```
`name` is the name of the header containing the actual IP address. recommended value is "X-Forwarded-For".

`cidr` is the address range of expected proxy servers. As a security measure, IP headers are only accepted from known proxy servers. Must be a valid cidr block notation. This may be specified multiple times. `cloudflare` and `cloudfront` are currently supported.

`maxhops` specifies a limiting number of forwards if using "X-Forwarded-For" or similar headers as the identifier. Recommended value is 5.

`strict`, if specified, will reject requests from unkown proxy IPs with a 403 status. If not specified, it will simply leave the original IP in place.

## Example

Simple usage to read `X-Forwarded-For` from cloudflare:

```Caddyfile

# tell caddy to process realip before other plugins
order realip first

realip {
  header "X-Forwarded-For"
  from cloudflare
  maxhops 5
}
```
