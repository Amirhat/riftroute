package bugreport

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/buildinfo"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/platform"
	"github.com/Amirhat/riftroute/internal/redact"
	"github.com/Amirhat/riftroute/internal/sysinfo"
)

// IssueURL is where users file reports (they attach the text themselves).
const IssueURL = "https://github.com/Amirhat/riftroute/issues/new"

// Client describes the program asking for the report (CLI or desktop app).
type Client struct {
	Name  string // "riftroute CLI", "RiftRoute app"
	Build domain.BuildInfo
}

// LocalUserNames lists account and full names on this machine — they turn up
// in paths, per-app rules and log lines, and identify the person.
func LocalUserNames(ctx context.Context) []string {
	var out []string
	if us, err := sysinfo.Users(ctx); err == nil {
		for _, u := range us {
			out = append(out, u.Username)
			if fn := strings.TrimSpace(u.FullName); fn != "" {
				out = append(out, fn)
				out = append(out, strings.Fields(fn)...) // "Jane Doe" → also "Jane", "Doe"
			}
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "root" {
		out = append(out, u.Username)
	}
	return out
}

// localRedactor knows this machine's host and user names — enough for the
// client's own lines and for a report built without the daemon.
func localRedactor(ctx context.Context) *redact.Redactor {
	r := redact.New()
	r.Add(redact.Host, platform.HostNames()...)
	r.Add(redact.User, LocalUserNames(ctx)...)
	return r
}

// clientSection describes the client and the service as the client sees it.
func clientSection(r *redact.Redactor, c Client, daemon *domain.Health) string {
	var b strings.Builder
	svc := platform.NewServiceManager().Status()
	fmt.Fprintf(&b, "\n## Client\n")
	fmt.Fprintf(&b, "client     %s %s\n", c.Name, buildinfo.Short(c.Build))
	fmt.Fprintf(&b, "os         %s\n", r.String(platform.OSDescription()))
	loaded := yn(svc.Loaded)
	if svc.Detail != "" {
		loaded += " (" + svc.Detail + ")"
	}
	fmt.Fprintf(&b, "service    %s: installed %s, loaded %s\n", svc.Manager, yn(svc.Installed), loaded)
	if daemon != nil {
		if m := buildinfo.Mismatch(c.Build, daemon.Build); m != "" {
			fmt.Fprintf(&b, "mismatch   %s\n", r.String(m))
		}
	}
	return b.String()
}

// WithClient adds the client's section to a daemon-rendered report, right
// after the header.
func WithClient(ctx context.Context, rep domain.BugReport, c Client, daemon *domain.Health) domain.BugReport {
	r := localRedactor(ctx)
	sec := clientSection(r, c, daemon)
	if i := strings.Index(rep.Text, "\n## "); i >= 0 {
		rep.Text = rep.Text[:i] + sec + rep.Text[i:]
	} else {
		rep.Text += sec
	}
	rep.Redactions += r.Count()
	return rep
}

// Offline builds what a report can contain when the daemon doesn't answer —
// the case where one is needed most: the client, the service state, why the
// daemon is unreachable, and its log if this user may read it.
func Offline(ctx context.Context, now time.Time, c Client, reachErr error) domain.BugReport {
	r := localRedactor(ctx)
	var b strings.Builder
	b.WriteString(Header(now))
	b.WriteString(clientSection(r, c, nil))
	fmt.Fprintf(&b, "\n## Daemon\nunreachable: %s\n", r.String(fmt.Sprint(reachErr)))
	if log, src := platform.DaemonLogTail(MaxLogLines); log != "" {
		fmt.Fprintf(&b, "\n## Daemon log (last %d lines of %s)\n", MaxLogLines, r.String(src))
		for _, l := range strings.Split(log, "\n") {
			b.WriteString(r.String(l) + "\n")
		}
	} else {
		b.WriteString("\n## Daemon log\n(not readable by this user — run with sudo to include it)\n")
	}
	return domain.BugReport{Text: b.String(), Redactions: r.Count(), GeneratedAt: now.UTC()}
}
