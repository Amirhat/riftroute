package telemetry

import (
	"bufio"
	"bytes"
	"runtime"
	"strconv"
	"strings"
)

// NewApp is this machine's App: the release (a build that isn't one is
// "dev"), and the OS, its major version, the Linux distribution and the
// architecture, each from the schema's lists.
func NewApp(version, channel string, service bool) App {
	major, distro := hostOS()
	a := App{
		Version: releaseVersion(version), Channel: Known(Channels, channel),
		OS: Known(OSes, runtime.GOOS), OSMajor: major, Arch: Known(Arches, runtime.GOARCH), Service: service,
	}
	if a.OS == "linux" {
		a.Distro = Known(Distros, distro)
	}
	return a
}

// releaseVersion is version when it's a release's (1.2.3, with or without
// a v), else "dev".
func releaseVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if reVersion.MatchString(v) {
		return v
	}
	return "dev"
}

// majorOf is the leading number of a version ("15.6.1" → 15, "24.04" → 24),
// 0 when there's none.
func majorOf(v string) int {
	head, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 || n > 9999 {
		return 0
	}
	return n
}

// osRelease reads os-release(5)'s ID and VERSION_ID's major number.
func osRelease(data []byte) (id string, major int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			major = majorOf(v)
		}
	}
	return id, major
}
