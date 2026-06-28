// Package dns handles domain-based routing (resolve A+AAAA, route results, with
// a background re-resolver for CDNs), split-DNS (per-domain resolver selection),
// and DNS leak checks (spec §6/§7.6). Built in M5/M6.
package dns
