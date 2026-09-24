package update

import "crypto/ed25519"

// TrustedKeys are the public keys release manifests must be signed with,
// by key ID. The private halves live only on the maintainer's machine
// (`riftroute-release keygen`); never on the server, never in CI.
//
// Up to two entries: the current key and, during a rotation, the next one —
// a release that adds the next key ships before the old key retires.
//
// Empty until the first key is generated: with no trusted key nothing can be
// verified, so nothing is installed automatically.
var TrustedKeys = map[string]ed25519.PublicKey{}
