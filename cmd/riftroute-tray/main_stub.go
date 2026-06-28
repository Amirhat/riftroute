//go:build !tray || !(darwin || linux)

// Stub so the cgo-free core build (`go build ./cmd/...`) compiles this package
// on every platform. The real menu-bar tray needs cgo + native libraries and is
// built explicitly with `-tags tray` (see `make tray`).
package main

import "fmt"

func main() {
	fmt.Println("riftroute-tray was built without tray support; rebuild with `make tray` (cgo + native tray libraries required).")
}
