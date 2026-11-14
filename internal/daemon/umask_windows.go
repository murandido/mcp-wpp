//go:build windows

package daemon

// withPrivateUmask is a no-op on Windows; the caller still chmods afterwards.
func withPrivateUmask[T any](fn func() (T, error)) (T, error) { return fn() }
