//go:build !windows

package daemon

import "syscall"

// withPrivateUmask runs fn with a umask that makes new files owner-only.
func withPrivateUmask[T any](fn func() (T, error)) (T, error) {
	old := syscall.Umask(0o177)
	defer syscall.Umask(old)
	return fn()
}
