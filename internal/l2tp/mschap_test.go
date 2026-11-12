package l2tp

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 2759 §9.2's example.
func TestMSCHAPv2Vectors(t *testing.T) {
	user, pass := "User", "clientPass"
	auth := unhex(t, "5B5D7C7D7B3F2F3E3C2C602132262628")
	peer := unhex(t, "21402324255E262A28295F2B3A337C7E")
	if got := hex.EncodeToString(challengeHash(peer, auth, user)); got != "d02e4386bce91226" {
		t.Errorf("ChallengeHash %s", got)
	}
	if got := hex.EncodeToString(ntPasswordHash(pass)); got != "44ebba8d5312b8d611474411f56989ae" {
		t.Errorf("PasswordHash %s", got)
	}
	nt := ntResponse(auth, peer, user, pass)
	if got := hex.EncodeToString(nt); got != "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df" {
		t.Errorf("NT-Response %s", got)
	}
	want := "S=407A5589115FD0D6209F510FE9C04566932CDA56"
	if got := authenticatorResponse(pass, nt, peer, auth, user); got != want {
		t.Errorf("AuthenticatorResponse %s", got)
	}
	resp := mschapv2Response(auth, peer, user, pass)
	if len(resp) != 49 {
		t.Fatalf("response %d bytes", len(resp))
	}
	if err := checkMSCHAPv2Success([]byte(want+" M=Welcome"), pass, resp, peer, auth, user); err != nil {
		t.Error(err)
	}
	if err := checkMSCHAPv2Success([]byte("S=0000000000000000000000000000000000000000"), pass, resp, peer, auth, user); err == nil {
		t.Error("a wrong authenticator response passed")
	}
	// A domain prefix isn't hashed.
	if got := hex.EncodeToString(challengeHash(peer, auth, `CORP\User`)); got != "d02e4386bce91226" {
		t.Errorf("with a domain: %s", got)
	}
}

func TestMSCHAPv2Failure(t *testing.T) {
	for msg, want := range map[string]string{
		"E=691 R=0 C=00 V=3 M=Authentication failure": "the server rejected the username or password",
		"E=648 R=0 V=3":                              "expired",
		"garbage":                                    "the server rejected the username or password",
	} {
		err := msFailure([]byte(msg))
		if !errors.Is(err, errRejected) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v", msg, err)
		}
	}
}
