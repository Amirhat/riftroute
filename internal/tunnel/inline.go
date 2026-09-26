package tunnel

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Creds is a username/password pair read from an auth-user-pass file.
type Creds struct {
	Username, Password string
}

// Inlined is a profile made self-contained by InlineFiles.
type Inlined struct {
	// Config is the profile text with every referenced file inlined.
	Config string
	// Creds come from an `auth-user-pass <file>` line; nil without one.
	Creds *Creds
	// Files are the files read, in profile order, each once — shown to the
	// user, so an import never reads more than they can see.
	Files []string
}

// fileDirectives take a path to key/cert material that must be inlined.
var fileDirectives = map[string]bool{
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true,
	"tls-crypt-v2": true, "pkcs12": true, "extra-certs": true, "crl-verify": true,
}

// maxRefFileBytes caps each file a profile refers to (a PKCS#12 bundle is a
// few KiB); the whole inlined profile is capped at maxProfileBytes, Parse's
// limit.
const maxRefFileBytes = 256 << 10

// ReadProfileFile reads a profile: a regular file of at most maxProfileBytes.
func ReadProfileFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	data, err := readRegular(fi, func() (*os.File, error) { return os.Open(path) }, maxProfileBytes)
	if err != nil {
		return "", fmt.Errorf("%s %w", filepath.Base(path), err)
	}
	return string(data), nil
}

// InlineFiles rewrites a profile so it is self-contained: each key/cert
// directive that names a file becomes an inline <block>, with relative paths
// resolved against dir, the profile's folder. An `auth-user-pass <file>`
// line becomes a bare `auth-user-pass`, and the file's credentials are
// returned instead. Clients (the CLI, the GUI) run this as the user before
// sending a profile to the daemon, so a profile can never pull in root's
// files.
//
// Nor can it pull in the user's: a downloaded profile naming
// ~/.aws/credentials as its auth-user-pass file would send the first two
// lines to its server. So only regular files in dir's tree are read —
// symlinks are resolved first, and anything that ends up outside is refused
// — each at most maxRefFileBytes. The credentials file, the one whose
// content goes to the server, must be right in dir — not in a folder under
// it (a profile in ~/Downloads, or in ~, would otherwise reach everything
// below) — and not hidden (a dotfile). The files read are listed in the
// result.
func InlineFiles(text, dir string) (*Inlined, error) {
	res := &Inlined{}
	var (
		out  []string
		size int
		pd   *profileDir
	)
	defer func() {
		if pd != nil {
			pd.close()
		}
	}()
	add := func(ls ...string) error {
		for _, l := range ls {
			out = append(out, l)
			size += len(l) + 1
		}
		if size > maxProfileBytes {
			return fmt.Errorf("with its files inlined, the profile is larger than %d KiB", maxProfileBytes>>10)
		}
		return nil
	}
	// read returns a referenced file's content, and records it in Files.
	read := func(ln int, name, ref string) ([]byte, error) {
		if pd == nil {
			var err error
			if pd, err = openProfileDir(dir); err != nil {
				return nil, fmt.Errorf("line %d: %s file: %w", ln, name, err)
			}
		}
		data, path, err := pd.read(ref, name == "auth-user-pass")
		if err != nil {
			return nil, fmt.Errorf("line %d: %s file %s", ln, name, err)
		}
		if !slices.Contains(res.Files, path) {
			res.Files = append(res.Files, path)
		}
		return data, nil
	}

	rows := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i := 0; i < len(rows); i++ {
		row := rows[i]
		raw := strings.TrimSpace(row)
		if strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">") && !strings.HasPrefix(raw, "</") {
			// Copy an existing inline block through untouched.
			end := "</" + raw[1:]
			if err := add(row); err != nil {
				return nil, err
			}
			for i++; i < len(rows); i++ {
				if err := add(rows[i]); err != nil {
					return nil, err
				}
				if strings.TrimSpace(rows[i]) == end {
					break
				}
			}
			continue
		}
		toks, err := tokenize(raw)
		if err != nil || len(toks) < 2 {
			if err := add(row); err != nil {
				return nil, err
			}
			continue
		}
		name, ref := strings.TrimPrefix(toks[0], "--"), toks[1]
		switch {
		case ref == "[inline]":
			err = add(row)
		case name == "auth-user-pass":
			var data []byte
			if data, err = read(i+1, name, ref); err != nil {
				return nil, err
			}
			ls := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			res.Creds = &Creds{Username: strings.TrimSpace(ls[0])}
			if len(ls) > 1 {
				res.Creds.Password = strings.TrimSpace(ls[1])
			}
			err = add("auth-user-pass")
		case fileDirectives[name]:
			if name == "crl-verify" && len(toks) > 2 && toks[2] == "dir" {
				return nil, fmt.Errorf("line %d: a CRL directory can't be inlined", i+1)
			}
			var data []byte
			if data, err = read(i+1, name, ref); err != nil {
				return nil, err
			}
			body := strings.TrimRight(string(data), "\n")
			if name == "pkcs12" {
				body = base64.StdEncoding.EncodeToString(data)
			}
			if name == "tls-auth" && len(toks) > 2 {
				if err := add("key-direction " + toks[2]); err != nil {
					return nil, err
				}
			}
			err = add("<"+name+">", body, "</"+name+">")
		default:
			err = add(row)
		}
		if err != nil {
			return nil, err
		}
	}
	res.Config = strings.Join(out, "\n")
	return res, nil
}

// profileDir reads files from a profile's folder, and only from there.
type profileDir struct {
	dir  string   // the folder, absolute, as the user named it
	real string   // the same with symlinks resolved
	root *os.Root // opened on real: opens can't leave it, even by a symlink swapped in later
}

func openProfileDir(dir string) (*profileDir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, err
	}
	return &profileDir{dir: abs, real: real, root: root}, nil
}

func (d *profileDir) close() { _ = d.root.Close() }

var errOutside = errors.New("is outside the profile's folder; RiftRoute only reads files next to the profile or in folders under it")

// read returns the content of the file ref names and the path it was read
// from (under the folder as the user named it). Its errors complete a
// sentence that starts with the reference.
func (d *profileDir) read(ref string, creds bool) ([]byte, string, error) {
	lexical, ok := d.local(ref)
	if !ok {
		return nil, "", fmt.Errorf("%s %w", ref, errOutside)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(d.real, lexical))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", ref, err)
	}
	rel, err := filepath.Rel(d.real, resolved)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, "", fmt.Errorf("%s %w", ref, errOutside)
	}
	if creds && (hidden(lexical) || hidden(rel)) {
		return nil, "", fmt.Errorf("%s is hidden (a dotfile, or in a dot-folder); RiftRoute won't read a login from it — put it in a plain file next to the profile, or type it in", ref)
	}
	if creds && (!beside(lexical) || !beside(rel)) {
		return nil, "", fmt.Errorf("%s is in a folder under the profile's; RiftRoute reads a login only from a file right next to the profile — move it there, or type it in", ref)
	}
	fi, err := d.root.Stat(rel)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", ref, err)
	}
	data, err := readRegular(fi, func() (*os.File, error) { return d.root.Open(rel) }, maxRefFileBytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s %w", ref, err)
	}
	return data, filepath.Join(d.dir, rel), nil
}

// local returns ref as a path relative to the folder, or false if it
// lexically leaves it: `..` past the top, or an absolute path elsewhere.
func (d *profileDir) local(ref string) (string, bool) {
	if !filepath.IsAbs(ref) {
		rel := filepath.Clean(ref)
		return rel, filepath.IsLocal(rel)
	}
	for _, base := range []string{d.dir, d.real} {
		if rel, err := filepath.Rel(base, ref); err == nil && filepath.IsLocal(rel) {
			return rel, true
		}
	}
	return "", false
}

// beside reports whether a relative path names a file in the folder itself,
// not in a folder under it.
func beside(rel string) bool {
	return filepath.IsLocal(rel) && filepath.Dir(rel) == "."
}

// hidden reports whether a relative path is a dotfile or inside a dot-folder.
func hidden(rel string) bool {
	for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasPrefix(c, ".") && c != "." && c != ".." {
			return true
		}
	}
	return false
}

// readRegular reads a regular file of at most limit bytes. fi is its Stat,
// taken before open is called: opening a FIFO would block, and a device
// (/dev/zero) never ends. Its errors complete a sentence that starts with
// the file's name.
func readRegular(fi fs.FileInfo, open func() (*os.File, error), limit int) ([]byte, error) {
	tooLarge := fmt.Errorf("is larger than %d KiB", limit>>10)
	if !fi.Mode().IsRegular() {
		return nil, errors.New("is not a regular file")
	}
	if fi.Size() > int64(limit) {
		return nil, tooLarge
	}
	f, err := open()
	if err != nil {
		return nil, fmt.Errorf("can't be read: %w", err)
	}
	defer f.Close()
	if now, err := f.Stat(); err != nil || !os.SameFile(fi, now) {
		return nil, errors.New("changed while it was being read")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("can't be read: %w", err)
	}
	if len(data) > limit {
		return nil, tooLarge
	}
	return data, nil
}
