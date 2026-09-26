package main

import (
	"testing"
	"time"
)

func TestAgoReadsLikeAPerson(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                         "just now",
		59 * time.Second:          "just now",
		time.Minute + time.Second: "1 minute ago",
		38 * time.Minute:          "38 minutes ago",
		time.Hour:                 "1 hour ago",
		47 * time.Hour:            "47 hours ago",
		72 * time.Hour:            "3 days ago",
	} {
		if got := ago(d); got != want {
			t.Errorf("ago(%s) = %q, want %q", d, got, want)
		}
	}
}
