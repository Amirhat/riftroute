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

// wgSystem is Linux's: a tun device named rrwgN by the kernel, set up with
// ip(8), as the routing provider does.
func wgSystem() WGSystem { return linuxWG{} }

type linuxWG struct{}

func (linuxWG) CreateTUN(mtu int) (tun.Device, error) { return tun.CreateTUN("rrwg%d", mtu) }

func (linuxWG) Configure(ctx context.Context, iface string, addrs []netip.Addr, mtu int) error {
	for _, a := range addrs {
		args := []string{"-4", "address", "add", netip.PrefixFrom(a, 32).String(), "dev", iface}
		if a.Is6() {
			args = []string{"-6", "address", "add", netip.PrefixFrom(a, 128).String(), "dev", iface, "nodad"}
		}
		if err := ipCmd(ctx, args...); err != nil {
			return err
		}
	}
	return ipCmd(ctx, "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up")
}

func ipCmd(ctx context.Context, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)+" "+err.Error()))
	}
	return nil
}
