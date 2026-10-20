package main

// cloudflareRanges are Cloudflare's published proxy ranges, for VAULT_TRUSTED_PROXIES=cloudflare. They are embedded,
// never fetched at runtime: a start-up that depends on a third-party download could fail, or be fed ranges by whoever
// intercepts it. Cloudflare changes the list rarely; refresh it from the two URLs and update the date.
//
// Source: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6, copied on 2026-10-20.
var cloudflareRanges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}
