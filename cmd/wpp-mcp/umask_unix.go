//go:build !windows

package main

import "syscall"

// privateUmask makes every file the process creates (databases, WAL and SHM
// files, media cache, token) owner-only, whatever the caller's umask.
func privateUmask() { syscall.Umask(0o077) }
