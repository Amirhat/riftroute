//go:build linux

package main

import (
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/provider/linux"
)

func realProvider() provider.RouteProvider { return linux.New() }
