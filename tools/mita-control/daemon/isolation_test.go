package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlgrpc"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestDaemonChild(t *testing.T) {
	if os.Getenv("RW_MITA_TEST_CHILD") != "1" {
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	if err := serve(ctx, os.Getenv("RW_MITA_TEST_DIR"), os.Getenv("RW_MITA_TEST_SOCKET")); err != nil {
		t.Fatal(err)
	}
}

func startIsolatedServer(t *testing.T, username, password string) int {
	t.Helper()
	// Keep the Unix socket path below the kernel's length limit, even in CI.
	directory, err := os.MkdirTemp("", "rw-mi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	socket := filepath.Join(directory, "rpc.sock")
	var logs bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonChild$")
	cmd.Env = append(os.Environ(), "RW_MITA_TEST_CHILD=1", "RW_MITA_TEST_DIR="+directory, "RW_MITA_TEST_SOCKET="+socket)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon exit: %v: %s", err, logs.String())
			}
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("daemon did not stop within its grace period")
		}
	})
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := appctlgrpc.NewServerManagementServiceClient(conn)
	deadline := time.Now().Add(8 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		status, statusErr := client.GetStatus(ctx, &emptypb.Empty{})
		cancel()
		if statusErr == nil {
			if status.GetStatus() != pb.AppStatus_IDLE {
				t.Fatal("a new daemon must not automatically revive proxy listeners")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(statusErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.SetConfig(ctx, &pb.ServerConfig{
		PortBindings:     []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: pb.TransportProtocol_TCP.Enum()}},
		Users:            []*pb.User{{Name: proto.String(username), Password: proto.String(password)}},
		AdvancedSettings: &pb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Start(ctx, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestListenersRejectEachOthersCredentials(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux runtime integration is executed by GitHub Actions")
	}
	first := startIsolatedServer(t, "1", "first-password")
	second := startIsolatedServer(t, "2", "second-password")
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	target := echo.Addr().(*net.TCPAddr).Port
	for _, item := range []struct {
		port           int
		user, password string
		allowed        bool
	}{
		{first, "1", "first-password", true},
		{second, "2", "second-password", true},
		{second, "1", "first-password", false},
		{first, "2", "second-password", false},
	} {
		err := exchange(item.port, target, item.user, item.password)
		if (err == nil) != item.allowed {
			t.Fatalf("listener %d user %s: allowed=%t, error=%v", item.port, item.user, item.allowed, err)
		}
	}
}

func exchange(port, target int, username, password string) error {
	mux := protocol.NewMux(true).
		SetClientUserNamePassword(username, cipher.HashPassword([]byte(password), []byte(username))).
		SetEndpoints([]protocol.UnderlayProperties{protocol.NewUnderlayProperties(1400, common.StreamTransport, nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})})
	defer mux.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := mux.DialContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(target))
	if _, err := conn.Write(request); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fmt.Errorf("SOCKS connect was rejected")
	}
	remaining := 6
	if reply[3] == 4 {
		remaining = 18
	} else if reply[3] != 1 {
		return fmt.Errorf("unexpected bound address")
	}
	if _, err := io.ReadFull(conn, make([]byte, remaining)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("isolated")); err != nil {
		return err
	}
	response := make([]byte, 8)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if string(response) != "isolated" {
		return fmt.Errorf("unexpected proxy response")
	}
	return nil
}
