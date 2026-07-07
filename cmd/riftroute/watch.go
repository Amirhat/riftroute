package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
)

func watchCmd() *cobra.Command {
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Live TUI: status, drift, VPN, profiles, and recent activity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if interval < time.Second {
				interval = 2 * time.Second
			}
			m := watchModel{cl: client(), interval: interval}
			p := tea.NewProgram(m, tea.WithAltScreen())
			_, err := p.Run()
			return err
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "refresh interval")
	return cmd
}

type watchModel struct {
	cl       *apiclient.Client
	interval time.Duration
	state    domain.State
	audit    []domain.AuditEvent
	err      error
	updated  time.Time
	w, h     int
}

type watchData struct {
	state domain.State
	audit []domain.AuditEvent
	err   error
}
type watchTick struct{}

func (m watchModel) Init() tea.Cmd { return tea.Batch(m.fetch(), tick(m.interval)) }

func (m watchModel) fetch() tea.Cmd {
	cl := m.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		st, err := cl.State(ctx)
		if err != nil {
			return watchData{err: err}
		}
		audit, _ := cl.Audit(ctx, time.Time{})
		if len(audit) > 8 {
			audit = audit[len(audit)-8:]
		}
		return watchData{state: st, audit: audit}
	}
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return watchTick{} })
}

func (m watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "r":
			return m, m.fetch()
		}
	case watchTick:
		return m, tea.Batch(m.fetch(), tick(m.interval))
	case watchData:
		m.state, m.err, m.updated = msg.state, msg.err, time.Now()
		if msg.err == nil {
			m.audit = msg.audit
		}
	}
	return m, nil
}

var (
	stTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	stOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	stWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	stErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	stDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	stKey   = lipgloss.NewStyle().Bold(true)
)

func (m watchModel) View() string {
	var b strings.Builder
	b.WriteString(stTitle.Render("RiftRoute — live") + "\n\n")
	if m.err != nil {
		b.WriteString(stErr.Render("daemon unreachable: "+m.err.Error()) + "\n\n")
		b.WriteString(stDim.Render("r refresh · q quit"))
		return b.String()
	}
	s := m.state
	health := stOK.Render("● " + string(s.Health.Daemon))
	if s.Health.Daemon != domain.DaemonOK {
		health = stWarn.Render("● " + string(s.Health.Daemon) + " (" + s.Health.Reason + ")")
	}
	fmt.Fprintf(&b, "%s  %s  provider=%s  up=%s\n", health,
		stDim.Render("v"+s.Health.Version), s.Health.Provider, fmtDur(s.Health.UptimeSeconds))

	vpn := stWarn.Render("down")
	if s.VPN.Active {
		vpn = stOK.Render("up " + strings.Join(s.VPN.Interfaces, ","))
	}
	drift := stOK.Render("in sync")
	if s.Drift.Pending {
		drift = stWarn.Render(fmt.Sprintf("PENDING +%d -%d", s.Drift.Adds, s.Drift.Dels))
	}
	ks := stDim.Render("off")
	if s.KillSwitch {
		ks = stErr.Render("ARMED")
	}
	fmt.Fprintf(&b, "VPN: %s   drift: %s   kill-switch: %s   managed: %d\n\n",
		vpn, drift, ks, s.ManagedRouteCount)

	b.WriteString(stTitle.Render("Profiles") + "\n")
	if len(s.Profiles) == 0 {
		b.WriteString(stDim.Render("  (none)") + "\n")
	}
	for _, p := range s.Profiles {
		mark := stDim.Render("○ off")
		if p.Enabled {
			mark = stOK.Render("● on ")
		}
		applied := ""
		if p.Enabled && !p.Applied {
			applied = stWarn.Render(" (not applied)")
		}
		fmt.Fprintf(&b, "  %s  %-16s %s %d rules%s\n", mark, p.Name, p.Mode, p.RuleCount, applied)
	}

	b.WriteString("\n" + stTitle.Render("Recent activity") + "\n")
	if len(m.audit) == 0 {
		b.WriteString(stDim.Render("  (none)") + "\n")
	}
	for _, e := range m.audit {
		res := stOK.Render(e.Result)
		if e.Rollback || strings.Contains(strings.ToLower(e.Result), "fail") || strings.Contains(strings.ToLower(e.Result), "roll") {
			res = stErr.Render(e.Result)
		}
		fmt.Fprintf(&b, "  %s %s %s %s\n", stDim.Render(e.TS.Format("15:04:05")), e.Actor, e.Action, res)
	}

	b.WriteString("\n" + stDim.Render(fmt.Sprintf("updated %s · ", m.updated.Format("15:04:05"))))
	b.WriteString(stKey.Render("r") + stDim.Render(" refresh · ") + stKey.Render("q") + stDim.Render(" quit"))
	return b.String()
}

func fmtDur(sec int64) string {
	d := time.Duration(sec) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", sec)
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
