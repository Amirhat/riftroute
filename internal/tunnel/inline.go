package tunnel

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
)

// Creds is a username/password pair read from an auth-user-pass file.
type Creds struct {
	Username, Password string
}

// fileDirectives take a path to key/cert material that must be inlined.
var fileDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "pkcs12": true, "extra-certs": true, "crl-verify": true,
}

// InlineFiles rewrites a profile so it is self-contained: each key/cert
// directive that names a file becomes an inline <block> read through read,
// with relative paths resolved against baseDir. An `auth-user-pass <file>`
// line becomes a bare `auth-user-pass`, and the file's credentials are
// returned instead. Clients (the CLI, the GUI) run this as the user before
// sending a profile to the daemon — so a profile can only ever pull in files
// the user can read, never root's.
func InlineFiles(text, baseDir string, read func(path string) ([]byte, error)) (string, *Creds, error) {
	var out []string
	var creds *Creds
	rows := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(rows); i++ {
		row := rows[i]
		raw := strings.TrimSpace(row)
		if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") && !strings.HasPrefix(raw, "</") {
			// Copy an existing inline block through untouched.
			end := "</" + raw[1:]
			out = append(out, row)
			for i++; i < len(rows); i++ {
				out = append(out, rows[i])
				if strings.TrimSpace(rows[i]) == end {
					break
				}
			}
			continue
		}
		toks, err := tokenize(raw)
		if err != nil || len(toks) < 2 {
			out = append(out, row)
			continue
		}
		name, path := strings.TrimPrefix(toks[0], "--"), toks[1]
		if path == "[inline]" {
			out = append(out, row)
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		switch {
		case name == "auth-user-pass":
			data, err := read(path)
			if err != nil {
				return "", nil, fmt.Errorf("line %d: auth-user-pass file: %w", i+1, err)
			}
			ls := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			creds = &Creds{Username: strings.TrimSpace(ls[0])}
			if len(ls) > 1 {
				creds.Password = strings.TrimSpace(ls[1])
			}
			out = append(out, "auth-user-pass")
		case fileDirectives[name]:
			if name == "crl-verify" && len(toks) > 2 && toks[2] == "dir" {
				return "", nil, fmt.Errorf("line %d: a CRL directory can't be inlined", i+1)
			}
			data, err := read(path)
			if err != nil {
				return "", nil, fmt.Errorf("line %d: %s file: %w", i+1, name, err)
			}
			body := strings.TrimRight(string(data), "\n")
			if name == "pkcs12" {
				body = base64.StdEncoding.EncodeToString(data)
			}
			if name == "tls-auth" && len(toks) > 2 {
				out = append(out, "key-direction "+toks[2])
			}
			out = append(out, "<"+name+">", body, "</"+name+">")
		default:
			out = append(out, row)
		}
	}
	return strings.Join(out, "\n"), creds, nil
}
