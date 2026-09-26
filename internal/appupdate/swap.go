package appupdate

import (
	"fmt"
	"os"
)

// swap puts next in target's place and keeps target as prev: two renames in
// one folder, so the app is never half-replaced. If the second fails, the
// first is undone. The running app keeps running from the moved files.
func swap(next, target, prev string) error {
	_ = os.RemoveAll(prev)
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
