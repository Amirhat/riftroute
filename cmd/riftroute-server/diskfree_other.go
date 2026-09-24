//go:build windows

package main

import "errors"

func diskFree(string) (uint64, error) { return 0, errors.New("not supported") }
