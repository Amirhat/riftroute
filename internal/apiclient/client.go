// Package apiclient is the shared Go client for the riftrouted UDS API. Both the
// CLI and the desktop app's Go side use it (spec §3.5/§11). The React frontend
// never imports this — it receives data via Wails bindings/events that the
// desktop Go side feeds from here.
package apiclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Amirhat/riftroute/internal/config"
	"github.com/Amirhat/riftroute/internal/domain"
	"github.com/Amirhat/riftroute/internal/safety"
	"github.com/Amirhat/riftroute/internal/sysinfo"
)

// ConfigResult is the response to a declarative config apply.
type ConfigResult struct {
	Issues []config.Issue `json:"issues,omitempty"`
	Plan   *domain.Plan   `json:"plan,omitempty"`
	Diff   *domain.Diff   `json:"diff,omitempty"`
	Result *safety.Result `json:"result,omitempty"`
	// ApplyError is set when the change itself persisted but the follow-up
	// reconcile failed (e.g. include mode with no live tunnel) — a partial
	// success the UI must distinguish from "nothing happened".
	ApplyError string `json:"apply_error,omitempty"`
}

// ApplyOptions are the wire options for an apply request.
type ApplyOptions struct {
	DryRun            bool `json:"dry_run"`
	Yes               bool `json:"yes"`
	ConfirmTimeoutSec int  `json:"confirm_timeout_sec"`
}

// ErrDaemonUnreachable indicates the daemon could not be contacted (socket
// missing, connection refused, timeout). Callers map this to a distinct exit
// code (spec §9).
var ErrDaemonUnreachable = errors.New("riftrouted is unreachable")

// APIError is a non-2xx response from the daemon.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("api error %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("api error %d", e.StatusCode)
}

// Client talks to riftrouted over its Unix domain socket.
type Client struct {
	socketPath string
	http       *http.Client
}

// New builds a client for the daemon socket at socketPath.
func New(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: false,
	}
	return &Client{
		socketPath: socketPath,
		http:       &http.Client{Transport: tr, Timeout: 15 * time.Second},
	}
}

// SocketPath returns the configured socket path.
func (c *Client) SocketPath() string { return c.socketPath }

func (c *Client) url(path string) string { return "http://unix" + path }

// do performs a request and decodes a JSON body into out (if non-nil).
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Transport-level failure: the daemon couldn't be reached.
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return parseAPIError(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func parseAPIError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = json.Unmarshal(b, &e)
	return &APIError{StatusCode: resp.StatusCode, Message: e.Error}
}

// --- typed read methods ---

// Ping checks daemon reachability, returning its reported version.
func (c *Client) Ping(ctx context.Context) (string, error) {
	var body struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, http.MethodGet, "/healthz", nil, &body); err != nil {
		return "", err
	}
	return body.Version, nil
}

// State fetches the aggregate daemon state.
func (c *Client) State(ctx context.Context) (domain.State, error) {
	var st domain.State
	err := c.do(ctx, http.MethodGet, "/state", nil, &st)
	return st, err
}

// Routes fetches the routing table, optionally filtered.
func (c *Client) Routes(ctx context.Context, family domain.Family, owner domain.Owner) ([]domain.Route, error) {
	path := "/routes"
	q := ""
	if family != "" {
		q = "family=" + string(family)
	}
	if owner != "" {
		if q != "" {
			q += "&"
		}
		q += "owner=" + string(owner)
	}
	if q != "" {
		path += "?" + q
	}
	var body struct {
		Routes []domain.Route `json:"routes"`
	}
	err := c.do(ctx, http.MethodGet, path, nil, &body)
	return body.Routes, err
}

// Rules fetches Linux policy rules for a family.
func (c *Client) Rules(ctx context.Context, family domain.Family) ([]domain.PolicyRule, error) {
	path := "/rules"
	if family != "" {
		path += "?family=" + string(family)
	}
	var body struct {
		Rules []domain.PolicyRule `json:"rules"`
	}
	err := c.do(ctx, http.MethodGet, path, nil, &body)
	return body.Rules, err
}

// RouteOp deletes or replaces a single EXTERNAL route (one RiftRoute doesn't
// manage) through the plan-level Apply Protocol. newRoute is nil for delete.
func (c *Client) RouteOp(ctx context.Context, action string, route domain.Route, newRoute *domain.Route) (ConfigResult, error) {
	body, err := json.Marshal(map[string]any{
		"action": action, "route": route, "new_route": newRoute,
	})
	if err != nil {
		return ConfigResult{}, err
	}
	return c.configRequest(ctx, http.MethodPost, "/routes/ops", body)
}

// SystemUsers fetches the local user catalog (per-app picker source).
func (c *Client) SystemUsers(ctx context.Context) ([]sysinfo.User, error) {
	var body struct {
		Users []sysinfo.User `json:"users"`
	}
	err := c.do(ctx, http.MethodGet, "/system/users", nil, &body)
	return body.Users, err
}

// SystemApps fetches the per-app routing targets (Linux cgroup units).
func (c *Client) SystemApps(ctx context.Context) ([]sysinfo.App, error) {
	var body struct {
		Apps []sysinfo.App `json:"apps"`
	}
	err := c.do(ctx, http.MethodGet, "/system/apps", nil, &body)
	return body.Apps, err
}

// Interfaces fetches the interface list.
func (c *Client) Interfaces(ctx context.Context) ([]domain.Iface, error) {
	var body struct {
		Interfaces []domain.Iface `json:"interfaces"`
	}
	err := c.do(ctx, http.MethodGet, "/interfaces", nil, &body)
	return body.Interfaces, err
}

// DNS fetches resolver configuration.
func (c *Client) DNS(ctx context.Context) (domain.DNSState, error) {
	var dns domain.DNSState
	err := c.do(ctx, http.MethodGet, "/dns", nil, &dns)
	return dns, err
}

// Diff fetches the desired-vs-actual diff over managed routes.
func (c *Client) Diff(ctx context.Context) (domain.Diff, error) {
	var d domain.Diff
	err := c.do(ctx, http.MethodGet, "/diff", nil, &d)
	return d, err
}

// Conflicts fetches overlapping-route conflicts among enabled profiles.
func (c *Client) Conflicts(ctx context.Context) ([]domain.Conflict, error) {
	var body struct {
		Conflicts []domain.Conflict `json:"conflicts"`
	}
	err := c.do(ctx, http.MethodGet, "/conflicts", nil, &body)
	return body.Conflicts, err
}

// Explain asks where traffic to target goes.
func (c *Client) Explain(ctx context.Context, target string) (domain.RouteExplain, error) {
	var ex domain.RouteExplain
	err := c.do(ctx, http.MethodPost, "/route/explain", map[string]string{"target": target}, &ex)
	return ex, err
}

// Profiles fetches stored profiles.
func (c *Client) Profiles(ctx context.Context) ([]domain.Profile, error) {
	var body struct {
		Profiles []domain.Profile `json:"profiles"`
	}
	err := c.do(ctx, http.MethodGet, "/profiles", nil, &body)
	return body.Profiles, err
}

// Audit fetches audit events at or after since.
func (c *Client) Audit(ctx context.Context, since time.Time) ([]domain.AuditEvent, error) {
	path := "/audit"
	if !since.IsZero() {
		path += "?since=" + since.UTC().Format(time.RFC3339)
	}
	var body struct {
		Events []domain.AuditEvent `json:"events"`
	}
	err := c.do(ctx, http.MethodGet, path, nil, &body)
	return body.Events, err
}

// Plan returns the dry-run plan + diff for the current enabled profiles.
func (c *Client) Plan(ctx context.Context) (domain.Plan, domain.Diff, error) {
	var body struct {
		Plan domain.Plan `json:"plan"`
		Diff domain.Diff `json:"diff"`
	}
	err := c.do(ctx, http.MethodPost, "/plan", struct{}{}, &body)
	return body.Plan, body.Diff, err
}

// Apply reconciles to the enabled profiles via the Apply Protocol.
func (c *Client) Apply(ctx context.Context, opts ApplyOptions) (safety.Result, error) {
	var res safety.Result
	err := c.do(ctx, http.MethodPost, "/apply", opts, &res)
	return res, err
}

// Confirm keeps a pending interactive change.
func (c *Client) Confirm(ctx context.Context, txID string) (domain.TxResult, error) {
	var body struct {
		Result domain.TxResult `json:"result"`
	}
	err := c.do(ctx, http.MethodPost, "/confirm", map[string]string{"tx_id": txID}, &body)
	return body.Result, err
}

// Rollback reverts a pending change immediately.
func (c *Client) Rollback(ctx context.Context, txID string) (domain.TxResult, error) {
	var body struct {
		Result domain.TxResult `json:"result"`
	}
	err := c.do(ctx, http.MethodPost, "/rollback", map[string]string{"tx_id": txID}, &body)
	return body.Result, err
}

// SetKillSwitch enables or disables the egress kill switch.
func (c *Client) SetKillSwitch(ctx context.Context, enabled bool) (bool, error) {
	var body struct {
		KillSwitch bool `json:"kill_switch"`
	}
	err := c.do(ctx, http.MethodPost, "/killswitch", map[string]bool{"enabled": enabled}, &body)
	return body.KillSwitch, err
}

// Panic flushes all managed routes and restores baseline.
func (c *Client) Panic(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/panic", struct{}{}, nil)
}

// SetProfileEnabled enables or disables a profile by name. When apply is true it
// reconciles immediately (CLI quick toggle); when false it only stages the
// desired flag so the caller can preview + apply with commit-confirm (GUI).
func (c *Client) SetProfileEnabled(ctx context.Context, name string, enable, apply bool) (safety.Result, error) {
	action := "disable"
	if enable {
		action = "enable"
	}
	path := "/profiles/" + name + "/" + action
	if !apply {
		path += "?apply=false"
	}
	var res safety.Result
	err := c.do(ctx, http.MethodPost, path, struct{}{}, &res)
	return res, err
}

// ApplyConfig sends a declarative config file for validation + reconcile. When
// the config has errors the result carries line-referenced Issues and the call
// returns an APIError (status 400) — but the ConfigResult is still populated.
func (c *Client) ApplyConfig(ctx context.Context, data []byte, format string, dryRun, yes bool) (ConfigResult, error) {
	path := "/config?format=" + format
	if dryRun {
		path += "&dry_run=1"
	}
	if yes {
		path += "&yes=1"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), bytes.NewReader(data))
	if err != nil {
		return ConfigResult{}, err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		return ConfigResult{}, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()
	var out ConfigResult
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode >= 400 {
		return out, &APIError{StatusCode: resp.StatusCode, Message: "config validation failed"}
	}
	return out, nil
}

// SaveProfile upserts a single GUI-built profile and reconciles. dryRun previews
// the plan without persisting; otherwise it persists then applies (interactive
// unless yes). Validation failures return an APIError (400) with the
// ConfigResult's Issues still populated (mirrors ApplyConfig).
func (c *Client) SaveProfile(ctx context.Context, p domain.Profile, dryRun, yes bool) (ConfigResult, error) {
	path := "/profiles"
	sep := "?"
	if dryRun {
		path += sep + "dry_run=1"
		sep = "&"
	}
	if yes {
		path += sep + "yes=1"
	}
	data, err := json.Marshal(p)
	if err != nil {
		return ConfigResult{}, err
	}
	return c.configRequest(ctx, http.MethodPost, path, data)
}

// DeleteProfile removes a profile by name and reconciles the remaining set
// (interactive unless yes).
func (c *Client) DeleteProfile(ctx context.Context, name string, yes bool) (ConfigResult, error) {
	path := "/profiles/" + url.PathEscape(name)
	if yes {
		path += "?yes=1"
	}
	return c.configRequest(ctx, http.MethodDelete, path, nil)
}

// configRequest issues a mutation that returns a ConfigResult, keeping the body
// (issues) even on a 4xx so the caller can render validation diagnostics.
func (c *Client) configRequest(ctx context.Context, method, path string, body []byte) (ConfigResult, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), reader)
	if err != nil {
		return ConfigResult{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return ConfigResult{}, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()
	var out ConfigResult
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode >= 400 {
		// Surface the daemon's actual reason ({"error": …} from writeErr) — a bare
		// "request failed" hides why a save/delete was refused from the user.
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &body)
		return out, &APIError{StatusCode: resp.StatusCode, Message: body.Error}
	}
	return out, nil
}

// Doctor runs the diagnostics battery.
func (c *Client) Doctor(ctx context.Context) (domain.DoctorReport, error) {
	var r domain.DoctorReport
	err := c.do(ctx, http.MethodGet, "/doctor", nil, &r)
	return r, err
}

// Leaks returns detected IPv6/DNS leaks.
func (c *Client) Leaks(ctx context.Context) ([]domain.Leak, error) {
	var body struct {
		Leaks []domain.Leak `json:"leaks"`
	}
	err := c.do(ctx, http.MethodGet, "/leaks", nil, &body)
	return body.Leaks, err
}

// Flows lists active connections correlated to their route/interface.
func (c *Client) Flows(ctx context.Context) ([]domain.Flow, error) {
	var body struct {
		Flows []domain.Flow `json:"flows"`
	}
	err := c.do(ctx, http.MethodGet, "/flows", nil, &body)
	return body.Flows, err
}

// Lists returns configured lists with cache metadata.
func (c *Client) Lists(ctx context.Context) ([]domain.List, error) {
	var body struct {
		Lists []domain.List `json:"lists"`
	}
	err := c.do(ctx, http.MethodGet, "/lists", nil, &body)
	return body.Lists, err
}

// RefreshList fetches a single remote list and updates its cache.
func (c *Client) RefreshList(ctx context.Context, name string) (domain.List, error) {
	var l domain.List
	err := c.do(ctx, http.MethodPost, "/lists/"+name+"/refresh", struct{}{}, &l)
	return l, err
}

// RefreshAllLists refreshes every remote list, returning the count refreshed.
func (c *Client) RefreshAllLists(ctx context.Context) (int, error) {
	var body struct {
		Refreshed int `json:"refreshed"`
	}
	err := c.do(ctx, http.MethodPost, "/lists/refresh", struct{}{}, &body)
	return body.Refreshed, err
}

// SaveList upserts a reusable list (GUI lists manager). Staging only: the change
// surfaces as drift; routes move on the next guarded Apply. On success the saved
// list (with any freshly fetched remote cache) is returned; validation failures
// return a *ValidationError with field-referenced issues.
func (c *Client) SaveList(ctx context.Context, l domain.List) (domain.List, error) {
	data, err := json.Marshal(l)
	if err != nil {
		return domain.List{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/lists"), bytes.NewReader(data))
	if err != nil {
		return domain.List{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return domain.List{}, fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		var cr ConfigResult
		if json.Unmarshal(body, &cr) == nil && len(cr.Issues) > 0 {
			return domain.List{}, &ValidationError{Issues: cr.Issues}
		}
		return domain.List{}, &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	}
	var out domain.List
	if err := json.Unmarshal(body, &out); err != nil {
		return domain.List{}, err
	}
	return out, nil
}

// DeleteList removes a list by name (refused with 409 while a profile references it).
func (c *Client) DeleteList(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/lists/"+url.PathEscape(name), nil, &struct{}{})
}

// SetAutoApply toggles the daemon's reconcile-on-network-change behavior at
// runtime (persisted across restarts).
func (c *Client) SetAutoApply(ctx context.Context, enabled bool) (bool, error) {
	var body struct {
		AutoApply bool `json:"auto_apply"`
	}
	err := c.do(ctx, http.MethodPut, "/autoapply", map[string]bool{"enabled": enabled}, &body)
	return body.AutoApply, err
}

// SplitDNS returns the persisted per-domain resolver routes.
func (c *Client) SplitDNS(ctx context.Context) ([]domain.SplitDNSRoute, error) {
	var routes []domain.SplitDNSRoute
	err := c.do(ctx, http.MethodGet, "/splitdns", nil, &routes)
	return routes, err
}

// SetSplitDNS validates, persists, and applies the split-DNS selection (empty
// clears it).
func (c *Client) SetSplitDNS(ctx context.Context, routes []domain.SplitDNSRoute) ([]domain.SplitDNSRoute, error) {
	if routes == nil {
		routes = []domain.SplitDNSRoute{}
	}
	data, err := json.Marshal(routes)
	if err != nil {
		return nil, err
	}
	res, err := c.configRequest(ctx, http.MethodPut, "/splitdns", data)
	if err != nil {
		if len(res.Issues) > 0 {
			return nil, &ValidationError{Issues: res.Issues}
		}
		return nil, err
	}
	return routes, nil
}

// ValidationError carries field-referenced validation issues from a rejected
// list/split-DNS save, so UIs can render them inline.
type ValidationError struct {
	Issues []config.Issue
}

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Issues))
	for _, i := range e.Issues {
		if i.Field != "" {
			parts = append(parts, i.Field+": "+i.Msg)
			continue
		}
		parts = append(parts, i.Msg)
	}
	return strings.Join(parts, "; ")
}

// Snapshots lists snapshot metadata (route payloads omitted).
func (c *Client) Snapshots(ctx context.Context) ([]domain.Snapshot, error) {
	var body struct {
		Snapshots []domain.Snapshot `json:"snapshots"`
	}
	err := c.do(ctx, http.MethodGet, "/snapshots", nil, &body)
	return body.Snapshots, err
}

// RestoreSnapshot restores a snapshot's captured profile set and reconciles
// (interactive by default — commit-confirm guards the change).
func (c *Client) RestoreSnapshot(ctx context.Context, id string) (ConfigResult, error) {
	return c.configRequest(ctx, http.MethodPost, "/snapshots/"+url.PathEscape(id)+"/restore", nil)
}

// Events streams server-sent events, invoking handle for each, until ctx is
// canceled or the stream errors. The desktop Go side uses this to re-emit Wails
// runtime events to React.
func (c *Client) Events(ctx context.Context, handle func(domain.Event)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/events"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	// No client timeout for the long-lived stream.
	streamClient := &http.Client{Transport: c.http.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDaemonUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return parseAPIError(resp)
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !bytes.HasPrefix([]byte(line), []byte("data: ")) {
			continue // skip blank separators / comments
		}
		payload := line[len("data: "):]
		var ev domain.Event
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		handle(ev)
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return ctx.Err()
}
