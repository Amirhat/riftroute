//go:build !windows

package ipsec

import "syscall"

var sigTerm = syscall.SIGTERM
