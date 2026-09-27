package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// wgSystem is macOS's: a utun device, set up with ifconfig (by path, never
// from PATH: the daemon is root).
func wgSystem() WGSystem { return darwinWG{} }

type darwinWG struct{}

func (darwinWG) CreateTUN(mtu int) (tun.Device, error) { return tun.CreateTUN("utun", mtu) }

func (darwinWG) Configure(ctx context.Context, iface string, addrs []netip.Addr, mtu int) error {
	for _, a := range addrs {
		args := []string{iface, "inet", a.String(), a.String(), "netmask", "255.255.255.255", "alias"}
		if a.Is6() {
			args = []string{iface, "inet6", a.String(), "prefixlen", "128", "alias"}
		}
		if err := ifconfig(ctx, args...); err != nil {
			return err
		}
	}
	return ifconfig(ctx, iface, "mtu", strconv.Itoa(mtu), "up")
}

func ifconfig(ctx context.Context, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/sbin/ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)+" "+err.Error()))
	}
	return nil
}
