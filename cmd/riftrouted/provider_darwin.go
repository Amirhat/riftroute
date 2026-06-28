//go:build darwin

package main

import (
	"github.com/Amirhat/riftroute/internal/provider"
	"github.com/Amirhat/riftroute/internal/provider/macos"
)

func realProvider() provider.RouteProvider { return macos.New() }
