package tunnel

import "syscall"

// parentDeath has the kernel send openvpn SIGTERM when the daemon's thread
// that started it goes away — in practice, when the daemon dies: Go doesn't
// retire threads that aren't locked. The management socket closing does the
// rest elsewhere (management-signal).
func parentDeath(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGTERM }
