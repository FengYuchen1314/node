//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLeaseRetainsOneInodeAndRejectsConcurrentOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.pid")
	first, err := acquireLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireLease(path); err == nil {
		second.Close()
		t.Fatal("two owners")
	}
	before, _ := os.Stat(path)
	first.Close()
	second, err := acquireLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("lease inode replaced")
	}
}

func TestLeaseRejectsLegacyLivePIDAndUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "owner.pid")
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := acquireLease(path); err == nil {
		file.Close()
		t.Fatal("stole legacy owner")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := acquireLease(link); err == nil {
		file.Close()
		t.Fatal("followed symlink")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if file, err := acquireLease(path); err == nil {
		file.Close()
		t.Fatal("accepted public lease")
	}
}
