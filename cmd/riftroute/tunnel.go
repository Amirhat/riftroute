package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Amirhat/riftroute/internal/apiclient"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/tunnel"
)

func tunnelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Run an OpenVPN connection next to your main VPN, for chosen networks only",
		Long: "RiftRoute can run an OpenVPN profile itself as a split tunnel: only the routes you\n" +
			"list go into it. The server's redirect-gateway, pushed routes and pushed DNS are\n" +
			"ignored, so a VPN that already carries everything else (Windscribe, …) stays up.\n" +
			"Runs on the openvpn program (not the OpenVPN Connect app): on macOS RiftRoute\n" +
			"ships its own, installed with the daemon; on Linux, install your distribution's\n" +
			"openvpn package. `riftroute tunnel list` says what's missing on this system.",
	}
	cmd.AddCommand(tunnelListCmd(), tunnelAddCmd(), tunnelEditCmd(), tunnelUpCmd(), tunnelDownCmd(), tunnelRmCmd(), tunnelLogCmd())
	return cmd
}

func tunnelListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "status"},
		Short:   "Show tunnels and their state",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ts, err := client().Tunnels(cmd.Context())
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), ts)
			}
			defer printEngineProblem(cmd)
			if len(ts) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no tunnels — add one with: riftroute tunnel add <name> <profile.ovpn> --route <cidr>")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSTATE\tIFACE\tSERVER\tVIA\tROUTES")
			for _, t := range ts {
				server := t.Server
				if server == "" {
					server = strings.Join(t.Servers, ",")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, stateText(t), dash(t.Iface), server, t.Via, strings.Join(t.Routes, ", "))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			for _, t := range ts {
				if t.LastError != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "\n%s: %s\n", t.Name, t.LastError)
				}
			}
			return nil
		},
	}
}

func stateText(t domain.TunnelStatus) string {
	if t.Detail != "" && t.Detail != string(t.State) && t.State != domain.TunnelConnected {
		return string(t.State) + " (" + t.Detail + ")"
	}
	return string(t.State)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// tunnelFlags are the settings shared by add and edit.
type tunnelFlags struct {
	username      string
	passwordStdin bool
	routes        []string
	via           string
	autoConnect   bool
	connect       bool
}

// bind registers the flags. The password is never a flag value (it would
// sit in shell history and the process list): it's prompted for without echo,
// or piped in with --password-stdin.
func (f *tunnelFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.username, "username", "", "login username (asked for if the profile needs one)")
	cmd.Flags().BoolVar(&f.passwordStdin, "password-stdin", false, "read the password from piped stdin instead of prompting")
	cmd.Flags().StringArrayVar(&f.routes, "route", nil, "a CIDR or IP to send into the tunnel (repeatable)")
	cmd.Flags().StringVar(&f.via, "via", "", `how to reach the server: "direct" (bypass other VPNs, default) or "default" (through them)`)
	cmd.Flags().BoolVar(&f.autoConnect, "auto-connect", false, "connect whenever the daemon starts")
	cmd.Flags().BoolVar(&f.connect, "connect", false, "connect right after saving")
}

// stdinTerminal reports whether a command's stdin is a terminal, with its
// descriptor for reading a password without echo. Tests stand in for one.
var stdinTerminal = func(r io.Reader) (int, bool) {
	f, ok := r.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0, false
	}
	return int(f.Fd()), true
}

// checkPasswordStdin refuses --password-stdin on a terminal: that read shows
// the password as it's typed, while the prompt without the flag hides it.
func (f *tunnelFlags) checkPasswordStdin(cmd *cobra.Command) error {
	if _, tty := stdinTerminal(cmd.InOrStdin()); f.passwordStdin && tty {
		return fmt.Errorf("%w: --password-stdin is for a piped password; typed on a terminal it would show on screen. "+
			"Leave the flag off and you'll be asked for it without echo", errUsage)
	}
	return nil
}

// warnNoLogin says a password flag was ignored because the profile doesn't
// log in with a username and password.
func warnNoLogin(cmd *cobra.Command, flag string) {
	fmt.Fprintf(cmd.ErrOrStderr(), "warning: this profile doesn't log in with a username and password; %s is ignored\n", flag)
}

func tunnelAddCmd() *cobra.Command {
	var (
		f       tunnelFlags
		replace bool
	)
	cmd := &cobra.Command{
		Use:   "add <name> <profile.ovpn>",
		Short: "Import an OpenVPN profile as a tunnel",
		Example: "  riftroute tunnel add infra ~/Downloads/office.ovpn \\\n" +
			"    --route 192.168.70.0/24 --route 192.168.72.11 --connect",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.checkPasswordStdin(cmd); err != nil {
				return err
			}
			if _, err := findTunnel(cmd.Context(), args[0]); err == nil && !replace {
				return fmt.Errorf("a tunnel named %q already exists — change it with `riftroute tunnel edit %s`, or pass --replace", args[0], args[0])
			}
			text, creds, err := readProfile(cmd, args[1])
			if err != nil {
				return err
			}
			p, err := tunnel.Parse(text)
			if err != nil {
				return fmt.Errorf("%s: %w", args[1], err)
			}
			spec := domain.TunnelSpec{
				Name: args[0], Type: domain.TunnelOpenVPN, Config: text, Routes: f.routes,
				Via: domain.TunnelVia(f.via), AutoConnect: f.autoConnect, Username: f.username,
			}
			if creds != nil {
				spec.Username, spec.Password = orStr(spec.Username, creds.Username), creds.Password
			}
			if p.NeedsAuth {
				if err := askCreds(cmd, &spec, f.passwordStdin, p.InlineUser != ""); err != nil {
					return err
				}
			} else if f.passwordStdin {
				warnNoLogin(cmd, "--password-stdin")
			}
			if len(f.routes) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "note: no --route given; the tunnel will connect but carry nothing until you add routes")
			}
			return saveTunnel(cmd, spec, f.connect)
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&replace, "replace", false, "overwrite an existing tunnel of the same name")
	return cmd
}

func tunnelEditCmd() *cobra.Command {
	var (
		f        tunnelFlags
		profile  string
		askPass  bool
		noRoutes bool
	)
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "Change a tunnel's routes, login, profile, or options",
		Long: "Only the flags you pass change. --route replaces the whole route list;\n" +
			"--password-stdin or --ask-password replaces the saved password.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := f.checkPasswordStdin(cmd); err != nil {
				return err
			}
			cur, err := findTunnel(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			spec := domain.TunnelSpec{
				Name: cur.Name, Type: cur.Type, Routes: cur.Routes, Via: cur.Via, AutoConnect: cur.AutoConnect,
				Username: f.username,
			}
			if profile != "" {
				text, creds, err := readProfile(cmd, profile)
				if err != nil {
					return err
				}
				spec.Config = text
				if creds != nil {
					spec.Username, spec.Password = orStr(spec.Username, creds.Username), creds.Password
				}
			}
			if cmd.Flags().Changed("route") {
				spec.Routes = f.routes
			}
			if noRoutes {
				spec.Routes = []string{}
			}
			if cmd.Flags().Changed("via") {
				spec.Via = domain.TunnelVia(f.via)
			}
			if cmd.Flags().Changed("auto-connect") {
				spec.AutoConnect = f.autoConnect
			}
			if f.passwordStdin || askPass {
				// A replaced profile decides; otherwise the saved one does.
				needsAuth := cur.NeedsAuth
				if spec.Config != "" {
					if p, err := tunnel.Parse(spec.Config); err == nil {
						needsAuth = p.NeedsAuth
					}
				}
				switch {
				case !needsAuth && f.passwordStdin:
					warnNoLogin(cmd, "--password-stdin")
				case !needsAuth:
					warnNoLogin(cmd, "--ask-password")
				default:
					if err := askCreds(cmd, &spec, f.passwordStdin, true); err != nil {
						return err
					}
				}
			}
			return saveTunnel(cmd, spec, f.connect)
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&profile, "profile", "", "replace the OpenVPN profile")
	cmd.Flags().BoolVar(&askPass, "ask-password", false, "prompt for a new password")
	cmd.Flags().BoolVar(&noRoutes, "no-routes", false, "remove every route")
	return cmd
}

func tunnelUpCmd() *cobra.Command {
	var noWait bool
	cmd := &cobra.Command{
		Use:   "up <name>",
		Short: "Connect a tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return connectTunnel(cmd, args[0], !noWait)
		},
	}
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "return once the connection has started")
	return cmd
}

func tunnelDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down <name>",
		Short: "Disconnect a tunnel (its routes are removed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := client().DisconnectTunnel(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), st)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", st.Name, st.State)
			return nil
		},
	}
}

func tunnelLogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "log <name>",
		Short: "Show openvpn's recent output for a tunnel (why it won't connect)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lines, err := client().TunnelLog(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), lines)
			}
			if len(lines) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no output yet")
			}
			for _, l := range lines {
				fmt.Fprintln(cmd.OutOrStdout(), l)
			}
			return nil
		},
	}
}

func tunnelRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "rm <name>",
		Aliases: []string{"remove", "delete"},
		Short:   "Disconnect and delete a tunnel (its saved login too)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := client().DeleteTunnel(cmd.Context(), args[0]); err != nil {
				return err
			}
			if g.json {
				return printJSON(cmd.OutOrStdout(), map[string]string{"status": "deleted", "name": args[0]})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted tunnel %s\n", args[0])
			return nil
		},
	}
}

// readProfile reads a .ovpn and inlines the files it references — as the
// user running the CLI, and only from the profile's own folder — and lists
// the files it read, so the user sees everything the import pulled in.
func readProfile(cmd *cobra.Command, path string) (string, *tunnel.Creds, error) {
	text, err := tunnel.ReadProfileFile(path)
	if err != nil {
		return "", nil, err
	}
	res, err := tunnel.InlineFiles(text, filepath.Dir(path))
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(res.Files) > 0 {
		w := cmd.ErrOrStderr()
		fmt.Fprintf(w, "inlined %d file(s) the profile refers to:\n", len(res.Files))
		for _, f := range res.Files {
			fmt.Fprintf(w, "  %s\n", f)
		}
	}
	return res.Config, res.Creds, nil
}

// askCreds fills in the username/password, prompting on a terminal.
func askCreds(cmd *cobra.Command, spec *domain.TunnelSpec, fromStdin, haveUser bool) error {
	in := bufio.NewReader(cmd.InOrStdin())
	fd, tty := stdinTerminal(cmd.InOrStdin())
	if spec.Username == "" && !haveUser {
		if !tty {
			return errors.New("this profile logs in with a username: pass --username")
		}
		fmt.Fprint(cmd.ErrOrStderr(), "Username: ")
		u, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		spec.Username = strings.TrimSpace(u)
	}
	if spec.Password != "" && !fromStdin {
		return nil
	}
	switch {
	case fromStdin:
		pw, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		spec.Password = strings.TrimRight(pw, "\r\n")
	case tty:
		fmt.Fprint(cmd.ErrOrStderr(), "Password: ")
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		spec.Password = string(pw)
	default:
		return errors.New("this profile logs in with a password: pass --password-stdin")
	}
	return nil
}

func saveTunnel(cmd *cobra.Command, spec domain.TunnelSpec, connect bool) error {
	res, err := client().SaveTunnel(cmd.Context(), spec)
	var ve *apiclient.ValidationError
	if errors.As(err, &ve) {
		for _, i := range ve.Issues {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s: %s\n", i.Field, i.Msg)
		}
		return errors.New("tunnel not saved")
	}
	if err != nil {
		return err
	}
	for _, i := range res.Issues {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", i.Msg)
	}
	t := res.Tunnel
	if t == nil {
		return errors.New("the daemon saved the tunnel but didn't return it")
	}
	w := human(cmd)
	fmt.Fprintf(w, "saved tunnel %s (%s, via %s)\n", t.Name, strings.Join(t.Servers, ", "), t.Via)
	if len(t.Ignored) > 0 {
		fmt.Fprintf(w, "  ignored from the profile (RiftRoute handles these): %s\n", strings.Join(t.Ignored, ", "))
	}
	if len(t.Routes) > 0 {
		fmt.Fprintf(w, "  routes: %s\n", strings.Join(t.Routes, ", "))
	}
	if connect {
		return connectTunnel(cmd, t.Name, true) // its JSON is the one document
	}
	printEngineProblem(cmd)
	if g.json {
		return printJSON(cmd.OutOrStdout(), t)
	}
	return nil
}

// human is where a tunnel command's progress lines go: stdout, or stderr
// under --json so stdout carries exactly one JSON document.
func human(cmd *cobra.Command) io.Writer {
	if g.json {
		return cmd.ErrOrStderr()
	}
	return cmd.OutOrStdout()
}

// printEngineProblem tells the user, when openvpn isn't usable on the
// daemon's machine, what's wrong and how to install it there. It says
// nothing when tunnels can run (or the daemon predates the check).
func printEngineProblem(cmd *cobra.Command) bool {
	e, err := client().TunnelEngine(cmd.Context())
	if err != nil || e.Available {
		return false
	}
	w := cmd.ErrOrStderr()
	fmt.Fprintf(w, "\n%s — tunnels can't connect until it's fixed.\n", e.Problem)
	if in := e.Install; in != nil {
		if len(in.Commands) > 0 {
			fmt.Fprintf(w, "On %s, run:\n\n", in.System)
			for _, c := range in.Commands {
				fmt.Fprintf(w, "  %s\n", c)
			}
			fmt.Fprintln(w)
		}
		if in.Note != "" {
			fmt.Fprintln(w, in.Note)
		}
		if in.URL != "" {
			fmt.Fprintln(w, in.URL)
		}
	}
	fmt.Fprintln(w, "RiftRoute picks it up as soon as it's installed; no restart needed.")
	return true
}

// connectTunnel starts a tunnel and, with wait, follows it until it is up or
// has failed.
func connectTunnel(cmd *cobra.Command, name string, wait bool) error {
	ctx := cmd.Context()
	if printEngineProblem(cmd) {
		return fmt.Errorf("%s not connected", name)
	}
	st, err := client().ConnectTunnel(ctx, name)
	if err != nil {
		return err
	}
	if !wait {
		if g.json {
			return printJSON(cmd.OutOrStdout(), st)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", name, st.State)
		return nil
	}
	deadline := time.Now().Add(60 * time.Second)
	last := ""
	for time.Now().Before(deadline) {
		if st, err = findTunnel(ctx, name); err != nil {
			return err
		}
		switch st.State {
		case domain.TunnelConnected:
			if g.json {
				return printJSON(cmd.OutOrStdout(), st)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: connected on %s (%s) to %s\n", name, st.Iface, st.LocalIP, st.Server)
			if st.LastError != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  warning: %s\n", st.LastError)
			}
			return nil
		case domain.TunnelFailed, domain.TunnelDisconnected:
			return fmt.Errorf("%s: %s", name, orStr(st.LastError, string(st.State)))
		}
		if s := stateText(st); s != last && !g.json {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s\n", s)
			last = s
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	if st.LastError != "" {
		return fmt.Errorf("%s: still %s after 60s: %s", name, stateText(st), st.LastError)
	}
	return fmt.Errorf("%s: still %s after 60s — see `riftroute tunnel log %s`", name, stateText(st), name)
}

func findTunnel(ctx context.Context, name string) (domain.TunnelStatus, error) {
	ts, err := client().Tunnels(ctx)
	if err != nil {
		return domain.TunnelStatus{}, err
	}
	for _, t := range ts {
		if t.Name == name {
			return t, nil
		}
	}
	return domain.TunnelStatus{}, fmt.Errorf("no tunnel named %q", name)
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
