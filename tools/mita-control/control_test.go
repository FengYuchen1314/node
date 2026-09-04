package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeManagementClient struct {
	status          pb.AppStatus
	config          *pb.ServerConfig
	calls           []string
	failStartCount  int
	failReloadCount int
	failSetCount    int
	metricsJSON     string
}

func (f *fakeManagementClient) GetStatus(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.AppStatusMsg, error) {
	f.calls = append(f.calls, "status")
	return &pb.AppStatusMsg{Status: f.status.Enum()}, nil
}

func (f *fakeManagementClient) Start(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error) {
	f.calls = append(f.calls, "start")
	if f.failStartCount > 0 {
		f.failStartCount--
		return nil, errors.New("start failed")
	}
	f.status = pb.AppStatus_RUNNING
	return &emptypb.Empty{}, nil
}

func (f *fakeManagementClient) Stop(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error) {
	f.calls = append(f.calls, "stop")
	f.status = pb.AppStatus_IDLE
	return &emptypb.Empty{}, nil
}

func (f *fakeManagementClient) GetConfig(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ServerConfig, error) {
	f.calls = append(f.calls, "config")
	return proto.Clone(f.config).(*pb.ServerConfig), nil
}

func (f *fakeManagementClient) SetConfig(_ context.Context, config *pb.ServerConfig, _ ...grpc.CallOption) (*pb.ServerConfig, error) {
	f.calls = append(f.calls, "set")
	if f.failSetCount > 0 {
		f.failSetCount--
		return nil, errors.New("set failed")
	}
	f.config = proto.Clone(config).(*pb.ServerConfig)
	return proto.Clone(config).(*pb.ServerConfig), nil
}

func (f *fakeManagementClient) Reload(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error) {
	f.calls = append(f.calls, "reload")
	if f.failReloadCount > 0 {
		f.failReloadCount--
		return nil, errors.New("reload failed")
	}
	return &emptypb.Empty{}, nil
}

func (f *fakeManagementClient) GetMetrics(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.Metrics, error) {
	f.calls = append(f.calls, "metrics")
	return &pb.Metrics{Json: proto.String(f.metricsJSON)}, nil
}

func (f *fakeManagementClient) GetVersion(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.Version, error) {
	f.calls = append(f.calls, "version")
	return &pb.Version{Major: proto.Uint32(3), Minor: proto.Uint32(36), Patch: proto.Uint32(0)}, nil
}

func TestSyncServerLeavesEquivalentRunningConfigAlone(t *testing.T) {
	requested := testConfig(443, "alice", "secret")
	stored, err := prepareDesiredConfig(requested)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{status: pb.AppStatus_RUNNING, config: stored}

	result, controlErr := syncServer(context.Background(), client, requested)
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if result.Operation != operationUnchanged {
		t.Fatalf("operation = %q, want %q", result.Operation, operationUnchanged)
	}
	assertCalls(t, client.calls, []string{"status", "version", "config"})
}

func TestPrepareDesiredConfigHashesPasswordWithoutMutatingRequest(t *testing.T) {
	requested := testConfig(443, "alice", "secret")
	prepared, err := prepareDesiredConfig(requested)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.GetUsers()[0].GetPassword() != "" {
		t.Fatal("prepared config retained a plaintext password")
	}
	if prepared.GetUsers()[0].GetHashedPassword() == "" {
		t.Fatal("prepared config does not contain a hashed password")
	}
	if requested.GetUsers()[0].GetPassword() != "secret" {
		t.Fatal("prepareDesiredConfig() mutated its input")
	}
}

func TestPrepareDesiredConfigAllowsNoUsers(t *testing.T) {
	requested := testConfig(443, "alice", "secret")
	requested.Users = nil
	prepared, err := prepareDesiredConfig(requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.GetUsers()) != 0 {
		t.Fatalf("users = %d, want 0", len(prepared.GetUsers()))
	}
}

func TestSyncServerStartsWithNoUsers(t *testing.T) {
	requested := testConfig(443, "alice", "secret")
	requested.Users = nil
	client := &fakeManagementClient{status: pb.AppStatus_IDLE, config: &pb.ServerConfig{}}

	result, controlErr := syncServer(context.Background(), client, requested)
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if result.Operation != operationStarted || result.Status != pb.AppStatus_RUNNING.String() {
		t.Fatalf("result = %#v, want STARTED/RUNNING", result)
	}
	if len(client.config.GetUsers()) != 0 {
		t.Fatalf("users = %d, want 0", len(client.config.GetUsers()))
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "set", "start"})
}

func TestSyncServerReloadsUserOnlyChange(t *testing.T) {
	previous, err := prepareDesiredConfig(testConfig(443, "alice", "old-secret"))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{status: pb.AppStatus_RUNNING, config: previous}

	result, controlErr := syncServer(context.Background(), client, testConfig(443, "alice", "new-secret"))
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if result.Operation != operationReloaded {
		t.Fatalf("operation = %q, want %q", result.Operation, operationReloaded)
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "set", "reload"})
}

func TestSyncServerReloadsLoggingOnlyChange(t *testing.T) {
	previous, err := prepareDesiredConfig(testConfig(443, "alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	requested := testConfig(443, "alice", "secret")
	requested.LoggingLevel = pb.LoggingLevel_DEBUG.Enum()
	client := &fakeManagementClient{status: pb.AppStatus_RUNNING, config: previous}

	result, controlErr := syncServer(context.Background(), client, requested)
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if result.Operation != operationReloaded {
		t.Fatalf("operation = %q, want %q", result.Operation, operationReloaded)
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "set", "reload"})
}

func TestSyncServerRestartsForPortChange(t *testing.T) {
	previous, err := prepareDesiredConfig(testConfig(443, "alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{status: pb.AppStatus_RUNNING, config: previous}

	result, controlErr := syncServer(context.Background(), client, testConfig(8443, "alice", "secret"))
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	if result.Operation != operationRestarted {
		t.Fatalf("operation = %q, want %q", result.Operation, operationRestarted)
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "stop", "set", "start"})
}

func TestSyncServerRollsBackFailedReload(t *testing.T) {
	previous, err := prepareDesiredConfig(testConfig(443, "alice", "old-secret"))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{
		status:          pb.AppStatus_RUNNING,
		config:          previous,
		failReloadCount: 1,
	}

	_, controlErr := syncServer(context.Background(), client, testConfig(443, "alice", "new-secret"))
	if controlErr == nil {
		t.Fatal("syncServer() succeeded, want reload error")
	}
	if !controlErr.RollbackAttempted || !controlErr.RollbackSucceeded {
		t.Fatalf("rollback = attempted:%v succeeded:%v, want true/true", controlErr.RollbackAttempted, controlErr.RollbackSucceeded)
	}
	if !proto.Equal(client.config, previous) {
		t.Fatal("rollback did not restore previous config")
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "set", "reload", "set", "reload"})
}

func TestSyncServerRollsBackFailedRestart(t *testing.T) {
	previous, err := prepareDesiredConfig(testConfig(443, "alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeManagementClient{
		status:         pb.AppStatus_RUNNING,
		config:         previous,
		failStartCount: 1,
	}

	_, controlErr := syncServer(context.Background(), client, testConfig(8443, "alice", "secret"))
	if controlErr == nil {
		t.Fatal("syncServer() succeeded, want start error")
	}
	if !controlErr.RollbackAttempted || !controlErr.RollbackSucceeded {
		t.Fatalf("rollback = attempted:%v succeeded:%v, want true/true", controlErr.RollbackAttempted, controlErr.RollbackSucceeded)
	}
	if client.status != pb.AppStatus_RUNNING {
		t.Fatalf("status = %s, want RUNNING", client.status)
	}
	if !proto.Equal(client.config, previous) {
		t.Fatal("rollback did not restore previous config")
	}
	assertCalls(t, client.calls, []string{"status", "version", "config", "stop", "set", "start", "stop", "set", "start"})
}

func TestReadStatusKeepsInt64MetricsExact(t *testing.T) {
	client := &fakeManagementClient{
		status:      pb.AppStatus_RUNNING,
		config:      testConfig(443, "alice", "secret"),
		metricsJSON: `{"users":{"alice":{"UploadBytes":9223372036854775807,"DownloadBytes":-9223372036854775808}}}`,
	}

	result, controlErr := readStatus(context.Background(), client)
	if controlErr != nil {
		t.Fatal(controlErr)
	}
	users := result.Metrics["users"].(map[string]any)
	alice := users["alice"].(map[string]any)
	if got := alice["UploadBytes"]; got != "9223372036854775807" {
		t.Fatalf("UploadBytes = %#v", got)
	}
	if got := alice["DownloadBytes"]; got != "-9223372036854775808" {
		t.Fatalf("DownloadBytes = %#v", got)
	}
}

func testConfig(port int32, name, password string) *pb.ServerConfig {
	return &pb.ServerConfig{
		PortBindings: []*pb.PortBinding{{
			Port:     proto.Int32(port),
			Protocol: pb.TransportProtocol_TCP.Enum(),
		}},
		Users: []*pb.User{{
			Name:     proto.String(name),
			Password: proto.String(password),
		}},
		LoggingLevel: pb.LoggingLevel_INFO.Enum(),
	}
}

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
}
