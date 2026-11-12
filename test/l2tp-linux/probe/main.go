// Command probe brings an L2TP session up with internal/l2tp over a Linux
// TUN, for test/l2tp-linux: it prints "UP …" once PPP is up, carries
// packets until SIGTERM, then hangs up. A failure prints "FAIL <why>" and
// exits 1.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Amirhat/riftroute/internal/l2tp"
	"golang.zx2c4.com/wireguard/tun"
)

const offset = 16 // room for the virtio header the Linux TUN may use

func main() {
	server := flag.String("server", "", "the server's address")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	iface := flag.String("iface", "l2tp0", "the TUN's name")
	encrypted := flag.Bool("encrypted", false, "IPsec protects the socket (allows PAP)")
	flag.Parse()

	fail := func(err error) {
		fmt.Println("FAIL", err)
		os.Exit(1)
	}
	srv, err := netip.ParseAddr(*server)
	if err != nil {
		fail(err)
	}
	// Source port 1701 too, as servers expect.
	c, err := net.DialUDP("udp", &net.UDPAddr{Port: 1701}, net.UDPAddrFromAddrPort(netip.AddrPortFrom(srv, 1701)))
	if err != nil {
		fail(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s, err := l2tp.Dial(ctx, l2tp.Config{Conn: c, Username: *user, Password: *pass, Encrypted: *encrypted})
	cancel()
	if err != nil {
		fail(err)
	}
	dev, err := tun.CreateTUN(*iface, s.MTU())
	if err != nil {
		fail(err)
	}
	peer := s.PeerIP()
	if !peer.IsValid() {
		peer = s.LocalIP()
	}
	for _, args := range [][]string{
		{"addr", "add", s.LocalIP().String(), "peer", peer.String() + "/32", "dev", *iface},
		{"link", "set", *iface, "mtu", strconv.Itoa(s.MTU()), "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			fail(fmt.Errorf("ip %v: %v: %s", args, err, out))
		}
	}
	fmt.Printf("UP local=%s peer=%s dns=%v mtu=%d\n", s.LocalIP(), s.PeerIP(), s.DNS(), s.MTU())

	go func() { // TUN → server
		bufs := make([][]byte, dev.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, offset+65535)
		}
		sizes := make([]int, len(bufs))
		for {
			n, err := dev.Read(bufs, sizes, offset)
			if err != nil {
				return
			}
			for i := range n {
				_ = s.WritePacket(bufs[i][offset : offset+sizes[i]])
			}
		}
	}()
	go func() { // server → TUN
		for {
			p, err := s.ReadPacket()
			if err != nil {
				return
			}
			b := make([]byte, offset+len(p))
			copy(b[offset:], p)
			_, _ = dev.Write([][]byte{b}, offset)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		_ = s.Close()
		fmt.Println("CLOSED")
	case <-s.Done():
		fmt.Println("ENDED", s.Err())
	}
	_ = dev.Close()
	rx, tx := s.Counters()
	fmt.Printf("COUNTERS rx=%d tx=%d\n", rx, tx)
}
