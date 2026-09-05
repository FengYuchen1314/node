//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

// Never unlink a flock inode: otherwise two processes could lock different files at one path.
// Kernel ownership is released on exit, and is independent of PID reuse or container PID names.
func acquireLease(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
		}
	}()
	var info syscall.Stat_t
	if err = syscall.Fstat(fd, &info); err != nil {
		return nil, err
	}
	if info.Mode&syscall.S_IFMT != syscall.S_IFREG || info.Nlink != 1 || info.Uid != uint32(os.Getuid()) || info.Mode&0077 != 0 {
		return nil, errors.New("unsafe lease file")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	// Preserve conservative compatibility with the old PID-file lease. Never steal a
	// potentially live legacy owner, even if its PID might have been reused.
	legacy, err := io.ReadAll(io.LimitReader(file, 32))
	if err != nil {
		return nil, err
	}
	if len(legacy) != 0 {
		pid, parseErr := strconv.Atoi(string(legacy))
		if parseErr != nil || pid < 1 || syscall.Kill(pid, 0) != syscall.ESRCH {
			return nil, errors.New("legacy owner cannot be proven inactive")
		}
		if err = file.Truncate(0); err != nil {
			return nil, err
		}
	}
	if err = file.Sync(); err != nil {
		return nil, err
	}
	ok = true
	return file, nil
}

func holdLease(path string) error {
	file, err := acquireLease(path)
	if err != nil {
		return err
	}
	defer file.Close()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	parentGone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(parentGone) }()
	if _, err = fmt.Fprintln(os.Stdout, "READY"); err != nil {
		return err
	}
	select {
	case <-parentGone:
	case <-signals:
	}
	return nil
}
