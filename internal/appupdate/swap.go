package appupdate

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// swap puts next in target's place and keeps target as prev: two renames in
// one folder, so the app is never half-replaced. If the second fails, the
// first is undone. The running app keeps running from the moved files.
func swap(next, target, prev string) error {
	if err := clear(prev); err != nil {
		_ = os.RemoveAll(next)
		return err
	}
	if err := os.Rename(target, prev); err != nil {
		_ = os.RemoveAll(next)
		return fmt.Errorf("move the current app aside: %w", err)
	}
	if err := os.Rename(next, target); err != nil {
		if rerr := os.Rename(prev, target); rerr != nil {
			return fmt.Errorf("put the new app in place: %w (and putting the old one back failed: %v — it is at %s)", err, rerr, prev)
		}
		_ = os.RemoveAll(next)
		return fmt.Errorf("put the new app in place: %w", err)
	}
	return nil
}

// unswap puts prev back in target's place (the release in target was
// rejected), and removes what was there.
func unswap(target, prev string) error {
	if _, err := os.Lstat(prev); err != nil {
		return fmt.Errorf("the previous app isn't there any more: %w", err)
	}
	rejected := prev + ".rejected-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.Rename(target, rejected); err != nil {
		return fmt.Errorf("move the rejected app aside: %w", err)
	}
	if err := os.Rename(prev, target); err != nil {
		_ = os.Rename(rejected, target)
		return fmt.Errorf("put the previous app back: %w", err)
	}
	_ = os.RemoveAll(rejected)
	return nil
}

// clear makes room for the kept previous app. One that can't be removed
// whole (a file in it this user can't delete) is moved aside instead, so it
// never blocks an update.
func clear(prev string) error {
	if _, err := os.Lstat(prev); os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(prev); err == nil {
		return nil
	}
	if err := os.Rename(prev, prev+"-"+strconv.FormatInt(time.Now().UnixNano(), 36)); err != nil {
		return fmt.Errorf("make room for the previous app: %w", err)
	}
	return nil
}
