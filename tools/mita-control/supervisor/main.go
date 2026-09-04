//go:build linux

// A narrow lifetime supervisor for unmodified proxy cores. It never accepts shell commands.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func main() {
	binary := flag.String("binary", "", "absolute executable path")
	flag.Parse()
	if !filepath.IsAbs(*binary) {
		fmt.Fprintln(os.Stderr, "absolute core executable required")
		os.Exit(2)
	}
	// Pdeathsig is tied to the creating OS thread; keep it alive while the child runs.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	command := exec.Command(*binary, flag.Args()...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "core could not start")
		os.Exit(1)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	parentGone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(parentGone) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-exited:
		if err != nil {
			os.Exit(1)
		}
		return
	case <-parentGone:
	case <-signals:
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		<-exited
	}
}
