// rw-mita-daemon runs the upstream Mieru server with instance-scoped storage.
// Each process has one listener and its own user registry and metrics dump.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlgrpc"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/metrics"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func main() {
	directory := flag.String("state-dir", "", "absolute instance state directory")
	socket := flag.String("socket", "", "absolute private management socket")
	watchParent := flag.Bool("watch-parent", false, "stop when the Agent's stdin pipe closes")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *watchParent {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			cancel()
		}()
	}
	if err := serve(ctx, *directory, *socket); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, directory, socket string) error {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(socket) {
		return errors.New("instance state and socket paths must be absolute")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if err := os.Setenv("MITA_CONFIG_FILE", filepath.Join(directory, "server.pb")); err != nil {
		return err
	}
	if err := os.Setenv("MITA_UDS_PATH", socket); err != nil {
		return err
	}
	// Never revive a persisted credential set before the Agent reconciles it.
	if err := appctl.StoreServerConfig(&pb.ServerConfig{}); err != nil {
		return err
	}
	appctl.SetAppStatus(pb.AppStatus_IDLE)
	metrics.SetMetricsDumpFilePath(filepath.Join(directory, "metrics.pb"))
	if err := metrics.LoadMetricsFromDump(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load instance metrics: %w", err)
	}
	if err := metrics.EnableMetricsDump(); err != nil {
		return err
	}
	// The Agent removes stale sockets only after confirming the old child exited.
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	server := grpc.NewServer(grpc.MaxRecvMsgSize(appctl.MaxRecvMsgSize))
	appctl.SetServerRPCServerRef(server)
	service := appctl.NewServerManagementService()
	appctlgrpc.RegisterServerManagementServiceServer(server, service)
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
	case err = <-result:
	}
	stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, stopErr := service.Stop(stopCtx, &emptypb.Empty{})
	dumpErr := metrics.DumpMetricsNow()
	server.Stop()
	return errors.Join(err, stopErr, dumpErr)
}
