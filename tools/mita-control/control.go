package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlgrpc"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const rollbackTimeout = 12 * time.Second

type syncOperation string

const (
	operationUnchanged syncOperation = "UNCHANGED"
	operationStarted   syncOperation = "STARTED"
	operationReloaded  syncOperation = "RELOADED"
	operationRestarted syncOperation = "RESTARTED"
)

type syncResult struct {
	Status    string        `json:"status"`
	Operation syncOperation `json:"operation"`
	Version   string        `json:"version"`
}

type stopResult struct {
	Status    string `json:"status"`
	Operation string `json:"operation"`
}

type statusResult struct {
	Status  string         `json:"status"`
	Version string         `json:"version"`
	Metrics map[string]any `json:"metrics"`
}

type controlError struct {
	Stage             string `json:"stage"`
	Message           string `json:"message"`
	RollbackAttempted bool   `json:"rollbackAttempted"`
	RollbackSucceeded bool   `json:"rollbackSucceeded"`
}

func (e *controlError) Error() string {
	return fmt.Sprintf("%s: %s", e.Stage, e.Message)
}

type managementClient interface {
	GetStatus(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.AppStatusMsg, error)
	Start(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error)
	Stop(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error)
	GetConfig(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.ServerConfig, error)
	SetConfig(context.Context, *pb.ServerConfig, ...grpc.CallOption) (*pb.ServerConfig, error)
	Reload(context.Context, *emptypb.Empty, ...grpc.CallOption) (*emptypb.Empty, error)
	GetMetrics(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.Metrics, error)
	GetVersion(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.Version, error)
}

func dialManagementClient(socketPath string) (managementClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(appctl.MaxRecvMsgSize)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create Mita management client: %w", err)
	}
	return appctlgrpc.NewServerManagementServiceClient(conn), conn, nil
}

func prepareDesiredConfig(config *pb.ServerConfig) (*pb.ServerConfig, error) {
	desired := proto.Clone(config).(*pb.ServerConfig)
	desired.Users = appctlcommon.HashUserPasswords(desired.GetUsers(), false)
	normalizeConfig(desired)
	if err := appctl.ValidateFullServerConfig(desired); err != nil {
		return nil, fmt.Errorf("invalid Mita server configuration: %w", err)
	}
	return desired, nil
}

func syncServer(ctx context.Context, client managementClient, requested *pb.ServerConfig) (*syncResult, *controlError) {
	desired, err := prepareDesiredConfig(requested)
	if err != nil {
		return nil, newControlError("validate-config", err)
	}

	status, err := getStatus(ctx, client)
	if err != nil {
		return nil, newControlError("get-status", err)
	}
	if err := ensureStableStatus(status); err != nil {
		return nil, newControlError("get-status", err)
	}
	versionResponse, err := client.GetVersion(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, newControlError("get-version", err)
	}
	version := formatVersion(versionResponse)

	previous, err := client.GetConfig(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, newControlError("get-config", err)
	}
	previous = proto.Clone(previous).(*pb.ServerConfig)
	normalizeConfig(previous)

	wasRunning := status == pb.AppStatus_RUNNING
	if proto.Equal(previous, desired) {
		if wasRunning {
			return &syncResult{Status: pb.AppStatus_RUNNING.String(), Operation: operationUnchanged, Version: version}, nil
		}
		if _, err := client.Start(ctx, &emptypb.Empty{}); err != nil {
			return nil, newControlError("start", err)
		}
		return &syncResult{Status: pb.AppStatus_RUNNING.String(), Operation: operationStarted, Version: version}, nil
	}

	if wasRunning && isReloadOnlyChange(previous, desired) {
		if _, err := client.SetConfig(ctx, desired); err != nil {
			return nil, withRollback(newControlError("set-config", err), rollbackReload(ctx, client, previous))
		}
		if _, err := client.Reload(ctx, &emptypb.Empty{}); err != nil {
			return nil, withRollback(newControlError("reload", err), rollbackReload(ctx, client, previous))
		}
		return &syncResult{Status: pb.AppStatus_RUNNING.String(), Operation: operationReloaded, Version: version}, nil
	}

	if wasRunning {
		if _, err := client.Stop(ctx, &emptypb.Empty{}); err != nil {
			return nil, newControlError("stop", err)
		}
	}
	if _, err := client.SetConfig(ctx, desired); err != nil {
		return nil, withRollback(newControlError("set-config", err), rollbackRestart(ctx, client, previous, wasRunning))
	}
	if _, err := client.Start(ctx, &emptypb.Empty{}); err != nil {
		return nil, withRollback(newControlError("start", err), rollbackRestart(ctx, client, previous, wasRunning))
	}

	operation := operationRestarted
	if !wasRunning {
		operation = operationStarted
	}
	return &syncResult{Status: pb.AppStatus_RUNNING.String(), Operation: operation, Version: version}, nil
}

func stopServer(ctx context.Context, client managementClient) (*stopResult, *controlError) {
	status, err := getStatus(ctx, client)
	if err != nil {
		return nil, newControlError("get-status", err)
	}
	if err := ensureStableStatus(status); err != nil {
		return nil, newControlError("get-status", err)
	}
	if status != pb.AppStatus_RUNNING {
		return &stopResult{Status: status.String(), Operation: "ALREADY_STOPPED"}, nil
	}
	if _, err := client.Stop(ctx, &emptypb.Empty{}); err != nil {
		return nil, newControlError("stop", err)
	}
	return &stopResult{Status: pb.AppStatus_IDLE.String(), Operation: "STOPPED"}, nil
}

func readStatus(ctx context.Context, client managementClient) (*statusResult, *controlError) {
	status, err := getStatus(ctx, client)
	if err != nil {
		return nil, newControlError("get-status", err)
	}
	version, err := client.GetVersion(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, newControlError("get-version", err)
	}
	metricsResponse, err := client.GetMetrics(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, newControlError("get-metrics", err)
	}
	metrics, err := stringifyMetricNumbers(metricsResponse.GetJson())
	if err != nil {
		return nil, newControlError("parse-metrics", err)
	}
	return &statusResult{
		Status:  status.String(),
		Version: formatVersion(version),
		Metrics: metrics,
	}, nil
}

func formatVersion(version *pb.Version) string {
	return fmt.Sprintf("%d.%d.%d", version.GetMajor(), version.GetMinor(), version.GetPatch())
}

func getStatus(ctx context.Context, client managementClient) (pb.AppStatus, error) {
	response, err := client.GetStatus(ctx, &emptypb.Empty{})
	if err != nil {
		return pb.AppStatus_UNKNOWN, err
	}
	return response.GetStatus(), nil
}

func ensureStableStatus(status pb.AppStatus) error {
	switch status {
	case pb.AppStatus_IDLE, pb.AppStatus_RUNNING, pb.AppStatus_STOPPED:
		return nil
	case pb.AppStatus_STARTING, pb.AppStatus_STOPPING:
		return fmt.Errorf("Mita is busy in %s state", status.String())
	default:
		return fmt.Errorf("Mita returned unsupported %s state", status.String())
	}
}

func isReloadOnlyChange(previous, desired *pb.ServerConfig) bool {
	left := proto.Clone(previous).(*pb.ServerConfig)
	right := proto.Clone(desired).(*pb.ServerConfig)
	left.Users = nil
	right.Users = nil
	left.LoggingLevel = nil
	right.LoggingLevel = nil
	return proto.Equal(left, right)
}

func normalizeConfig(config *pb.ServerConfig) {
	sort.Slice(config.PortBindings, func(i, j int) bool {
		left := config.PortBindings[i]
		right := config.PortBindings[j]
		if left.GetProtocol() == right.GetProtocol() {
			if left.GetPort() == right.GetPort() {
				return left.GetPortRange() < right.GetPortRange()
			}
			return left.GetPort() < right.GetPort()
		}
		return left.GetProtocol() < right.GetProtocol()
	})
	sort.Slice(config.Users, func(i, j int) bool {
		return config.Users[i].GetName() < config.Users[j].GetName()
	})
}

func rollbackReload(ctx context.Context, client managementClient, previous *pb.ServerConfig) bool {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if _, err := client.SetConfig(rollbackCtx, previous); err != nil {
		return false
	}
	if _, err := client.Reload(rollbackCtx, &emptypb.Empty{}); err != nil {
		return false
	}
	return true
}

func rollbackRestart(ctx context.Context, client managementClient, previous *pb.ServerConfig, wasRunning bool) bool {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	succeeded := true
	if _, err := client.Stop(rollbackCtx, &emptypb.Empty{}); err != nil {
		succeeded = false
	}
	if _, err := client.SetConfig(rollbackCtx, previous); err != nil {
		return false
	}
	if wasRunning {
		if _, err := client.Start(rollbackCtx, &emptypb.Empty{}); err != nil {
			return false
		}
	}
	return succeeded
}

func newControlError(stage string, err error) *controlError {
	return &controlError{Stage: stage, Message: err.Error()}
}

func withRollback(operationErr *controlError, succeeded bool) *controlError {
	operationErr.RollbackAttempted = true
	operationErr.RollbackSucceeded = succeeded
	return operationErr
}
