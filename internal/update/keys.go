package update

import (
	"crypto/ed25519"
	"encoding/base64"
)

// TrustedKeys are the public keys release manifests must be signed with,
// by key ID. The private halves live only on the maintainer's machine
// (`riftroute-release keygen`); never on the server, never in CI.
//
// Up to two entries: the current key and, during a rotation, the next one —
// a release that adds the next key ships before the old key retires.
//
// Key history (never reuse an ID):
//   - rr-17019dba6c8f775a — first release key, generated 2026-09-26.
var TrustedKeys = map[string]ed25519.PublicKey{
	"rr-17019dba6c8f775a": mustKey("VveM5vbcIOT4MrsnEH84U8KKlPnupfnBTagJRsw6x/w="),
}

// mustKey decodes a base64 public key (a malformed entry is a build-time bug).
func mustKey(b64 string) ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("update: bad trusted key " + b64)
	}
	return ed25519.PublicKey(b)
}
