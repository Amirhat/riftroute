package l2tp

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MS-CHAPv2 is defined with MD4 (RFC 2759)
)

// chapMD5Response is CHAP-MD5's response (RFC 1994): MD5(id, secret,
// challenge).
func chapMD5Response(id uint8, secret string, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{id})
	h.Write([]byte(secret))
	h.Write(challenge)
	return h.Sum(nil)
}

// MS-CHAPv2 (RFC 2759). It's weak on its own; here IPsec encrypts it, and
// it checks the server: its success message proves it knows the password.

func ntPasswordHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// msUser is the user name MS-CHAPv2 hashes: without a "DOMAIN\" prefix.
func msUser(user string) string {
	if i := strings.LastIndexByte(user, '\\'); i >= 0 {
		return user[i+1:]
	}
	return user
}

func challengeHash(peer, auth []byte, user string) []byte {
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(msUser(user)))
	return h.Sum(nil)[:8]
}

// desKey spreads 7 bytes into an 8-byte DES key (parity bits ignored).
func desKey(k []byte) []byte {
	return []byte{
		k[0] & 0xfe,
		(k[0]<<7 | k[1]>>1) & 0xfe,
		(k[1]<<6 | k[2]>>2) & 0xfe,
		(k[2]<<5 | k[3]>>3) & 0xfe,
		(k[3]<<4 | k[4]>>4) & 0xfe,
		(k[4]<<3 | k[5]>>5) & 0xfe,
		(k[5]<<2 | k[6]>>6) & 0xfe,
		k[6] << 1,
	}
}

func challengeResponse(challenge, passwordHash []byte) []byte {
	z := make([]byte, 21)
	copy(z, passwordHash)
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		c, _ := des.NewCipher(desKey(z[7*i : 7*i+7])) // always 8 bytes
		blk := make([]byte, 8)
		c.Encrypt(blk, challenge)
		out = append(out, blk...)
	}
	return out
}

// ntResponse is the 24-byte NT-Response.
func ntResponse(auth, peer []byte, user, password string) []byte {
	return challengeResponse(challengeHash(peer, auth, user), ntPasswordHash(password))
}

var (
	magic1 = []byte("Magic server to client signing constant")
	magic2 = []byte("Pad to make it do more than one iteration")
)

// authenticatorResponse is the "S=…" the server must send back.
func authenticatorResponse(password string, nt, peer, auth []byte, user string) string {
	hh := md4.New()
	hh.Write(ntPasswordHash(password))
	h := sha1.New()
	h.Write(hh.Sum(nil))
	h.Write(nt)
	h.Write(magic1)
	digest := h.Sum(nil)
	h = sha1.New()
	h.Write(digest)
	h.Write(challengeHash(peer, auth, user))
	h.Write(magic2)
	return "S=" + strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// mschapv2Response is the 49-byte Response value: peer challenge, 8 zero
// bytes, NT-Response, flags.
func mschapv2Response(auth, peer []byte, user, password string) []byte {
	v := make([]byte, 0, 49)
	v = append(v, peer...)
	v = append(v, make([]byte, 8)...)
	v = append(v, ntResponse(auth, peer, user, password)...)
	return append(v, 0)
}

// checkMSCHAPv2Success checks a Success message's "S=" (response is the
// 49-byte Response we sent) against what the
// server must have computed.
func checkMSCHAPv2Success(msg []byte, password string, response, peer, auth []byte, user string) error {
	want := authenticatorResponse(password, response[24:48], peer, auth, user)
	got, _, _ := strings.Cut(string(msg), " ")
	if subtle.ConstantTimeCompare([]byte(strings.ToUpper(got)), []byte(want)) != 1 {
		return errors.New("the server accepted the login but couldn't prove it knows the password (MS-CHAPv2); it may not be the server you meant")
	}
	return nil
}

// errRejected: the server rejected the username or password. The phrase is
// the tunnels' own (failureCodes: "auth").
var errRejected = errors.New("the server rejected the username or password")

// msFailure turns an MS-CHAPv2 Failure message ("E=691 R=0 …") into an
// error.
func msFailure(msg []byte) error {
	e := ""
	for _, f := range bytes.Fields(msg) {
		if v, ok := bytes.CutPrefix(f, []byte("E=")); ok {
			e = string(v)
		}
	}
	switch e {
	case "648":
		return fmt.Errorf("%w: its password has expired (MS-CHAPv2 error 648)", errRejected)
	case "647":
		return fmt.Errorf("%w: the account is disabled (MS-CHAPv2 error 647)", errRejected)
	case "646":
		return fmt.Errorf("%w: it may not log in at this time (MS-CHAPv2 error 646)", errRejected)
	case "649":
		return fmt.Errorf("%w: the account has no permission to dial in (MS-CHAPv2 error 649)", errRejected)
	case "", "691":
		return errRejected
	}
	return fmt.Errorf("%w (MS-CHAPv2 error %s)", errRejected, printable([]byte(e)))
}
