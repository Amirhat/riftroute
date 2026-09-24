package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/Amirhat/riftroute/internal/update"
)

// keyFile is the on-disk release key: the ed25519 seed sealed with
// XChaCha20-Poly1305 under a key derived from the passphrase by scrypt. The
// public key and its ID sit beside it in the clear (they're public anyway),
// and are bound to the ciphertext as additional data.
type keyFile struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	PublicKey  string `json:"public_key"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// scrypt cost: ~0.5 s and 128 MiB on a laptop per unlock — cheap for one
// signature per release, expensive for a guesser holding a stolen file.
const scryptN, scryptR, scryptP = 1 << 17, 8, 1

func deriveKey(pw, salt []byte, n, r, p int) ([]byte, error) {
	return scrypt.Key(pw, salt, n, r, p, chacha20poly1305.KeySize)
}

func sealKey(priv ed25519.PrivateKey, pw []byte) ([]byte, error) {
	pub := priv.Public().(ed25519.PublicKey)
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	k, err := deriveKey(pw, salt, scryptN, scryptR, scryptP)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	kf := keyFile{
		Version: 1, KeyID: update.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub),
		KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP,
		Salt: base64.StdEncoding.EncodeToString(salt), Nonce: base64.StdEncoding.EncodeToString(nonce),
	}
	kf.Ciphertext = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, priv.Seed(), []byte(kf.KeyID)))
	return json.MarshalIndent(kf, "", "  ")
}

func openKey(blob, pw []byte) (ed25519.PrivateKey, error) {
	var kf keyFile
	if err := json.Unmarshal(blob, &kf); err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if kf.Version != 1 || kf.KDF != "scrypt" {
		return nil, errors.New("key file: unsupported format")
	}
	// Refuse parameters so weak they'd make the passphrase pointless, or so
	// large they'd hang the machine.
	if kf.N < 1<<15 || kf.N > 1<<20 || kf.R < 8 || kf.R > 32 || kf.P < 1 || kf.P > 4 {
		return nil, errors.New("key file: unexpected scrypt parameters")
	}
	salt, err1 := base64.StdEncoding.DecodeString(kf.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(kf.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(kf.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("key file: corrupt")
	}
	k, err := deriveKey(pw, salt, kf.N, kf.R, kf.P)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, []byte(kf.KeyID))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("wrong passphrase (or the key file was changed)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if update.KeyID(priv.Public().(ed25519.PublicKey)) != kf.KeyID {
		return nil, errors.New("key file: key ID doesn't match the key")
	}
	return priv, nil
}
