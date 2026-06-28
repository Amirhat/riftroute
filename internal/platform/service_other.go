//go:build !darwin && !linux

package platform

import "errors"

type noopManager struct{}

func newServiceManager() ServiceManager { return noopManager{} }

var errUnsupportedService = errors.New("service install is not supported on this platform")

func (noopManager) Status() ServiceStatus {
	return ServiceStatus{Manager: "unsupported"}
}
func (noopManager) Install(string, string) error { return errUnsupportedService }
func (noopManager) Uninstall() error             { return errUnsupportedService }
func (noopManager) Restart() error               { return errUnsupportedService }
