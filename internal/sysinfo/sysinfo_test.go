package sysinfo

import (
	"testing"
	"testing/fstest"
)

func TestParseDsclUsersFiltersServiceAccounts(t *testing.T) {
	out := `_mdnsresponder  65
root            0
amir            501
guest           502
_spotlight      89
`
	users := ParseDsclUsers(out, map[string]string{"amir": "Amir H"}, 500)
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3 (root, amir, guest): %+v", len(users), users)
	}
	if users[0].Username != "root" || users[1].Username != "amir" || users[2].Username != "guest" {
		t.Fatalf("wrong order/filter: %+v", users)
	}
	if users[1].FullName != "Amir H" {
		t.Fatalf("full name not joined: %+v", users[1])
	}
}

func TestParsePasswdFiltersAndSorts(t *testing.T) {
	content := `# comment
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bob:x:1001:1001:Bob B,,,:/home/bob:/bin/bash
alice:x:1000:1000:Alice A:/home/alice:/bin/zsh
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
`
	users := ParsePasswd(content, 1000)
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3: %+v", len(users), users)
	}
	if users[0].Username != "root" || users[1].Username != "alice" || users[2].Username != "bob" {
		t.Fatalf("wrong order: %+v", users)
	}
	if users[2].FullName != "Bob B" {
		t.Fatalf("gecos comma tail not stripped: %q", users[2].FullName)
	}
}

func TestCgroupAppsFindsUnits(t *testing.T) {
	fsys := fstest.MapFS{
		"system.slice/nginx.service/cgroup.procs":                          {},
		"system.slice/ssh.service/cgroup.procs":                            {},
		"user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-2211.scope/cgroup.procs": {},
		"system.slice/system-getty.slice/getty@tty1.service/cgroup.procs":  {},
		"init.scope/cgroup.procs":                                          {},
	}
	apps := CgroupApps(fsys)
	byValue := map[string]string{}
	for _, a := range apps {
		byValue[a.Value] = a.Name
	}
	if byValue["system.slice/nginx.service"] != "nginx" {
		t.Fatalf("nginx service missing: %+v", apps)
	}
	if byValue["init.scope"] != "init" {
		t.Fatalf("init scope missing: %+v", apps)
	}
	// The deep app scope sits past the depth cap — the walker must not hang or
	// include it, and the cap keeps the picker responsive.
	if _, ok := byValue["user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-2211.scope"]; ok {
		t.Fatalf("depth cap not applied: %+v", apps)
	}
}
