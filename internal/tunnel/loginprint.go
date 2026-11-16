package tunnel

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/scrypt"
)

// loginPrint fingerprints a login — the configuration and the username and
// password it logs in with — so "this very login has connected before"
// (#37's rule) survives restarts without the password in another place. It
// goes to disk (beside the definition, root-only), so it's a password hash:
// scrypt, salted with the configuration and username (deterministic: it's
// compared, never reversed). A few milliseconds, once per attempt.
func loginPrint(config, username, password string) string {
	salt := sha256.Sum256([]byte(config + "\x00" + username))
	k, err := scrypt.Key([]byte(password), salt[:], 1<<12, 8, 1, 32)
	if err != nil { // only for parameters out of range
		return ""
	}
	return hex.EncodeToString(k)
}
