// Package lists handles reusable rule lists: static sets and remote subscribable
// sources (HTTPS-only, size-limited, validated as CIDR/IP, checksummed, never
// executed — spec §12) with refresh, plus GeoIP/ASN lookup via an embeddable
// MMDB reader (spec §5/§6). Built in M5.
package lists
