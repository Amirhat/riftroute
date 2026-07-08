// Command devbridge exposes riftrouted's Unix socket on a local TCP port so
// the React frontend can run in a plain browser during development (`npm run
// dev` proxies /rr-api here — see vite.config.ts and src/dev/shim.ts).
//
//	go run ./tools/devbridge -uds /tmp/rr-dev.sock -tcp 127.0.0.1:8787
//
// Dev-only: binds loopback, no auth beyond the daemon's own peer-cred gate
// (the bridge process's uid is what the daemon sees).
package main

import (
	"flag"
	"io"
	"log"
	"net"
)

func main() {
	tcp := flag.String("tcp", "127.0.0.1:8787", "TCP address to listen on (loopback)")
	uds := flag.String("uds", "/tmp/rr-dev.sock", "riftrouted Unix socket to bridge to")
	flag.Parse()

	ln, err := net.Listen("tcp", *tcp)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("devbridge: %s ↔ %s", *tcp, *uds)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			u, err := net.Dial("unix", *uds)
			if err != nil {
				log.Printf("devbridge: daemon unreachable: %v", err)
				return
			}
			defer u.Close()
			go func() { _, _ = io.Copy(u, c) }()
			_, _ = io.Copy(c, u)
		}(c)
	}
}
