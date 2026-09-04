package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/metrics"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultSocketPath = "/var/run/mita/mita.sock"
	maxConfigBytes    = 8 << 20
	operationTimeout  = 20 * time.Second
)

type responseEnvelope struct {
	OK     bool          `json:"ok"`
	Result any           `json:"result,omitempty"`
	Error  *controlError `json:"error,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return writeFailure(output, newControlError("arguments", errors.New("operation is required")))
	}

	flags := flag.NewFlagSet("mita-control "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	socketPath := flags.String("socket", defaultSocketPath, "Mita management Unix socket")
	configPath := flags.String("config", "", "Mita server configuration JSON")
	dumpPath := flags.String("dump", "", "instance metrics dump file")
	if err := flags.Parse(args[1:]); err != nil {
		return writeFailure(output, newControlError("arguments", err))
	}
	if flags.NArg() != 0 {
		return writeFailure(output, newControlError("arguments", errors.New("unexpected positional arguments")))
	}
	if *socketPath == "" {
		return writeFailure(output, newControlError("arguments", errors.New("socket path is empty")))
	}
	if !filepath.IsAbs(*socketPath) {
		return writeFailure(output, newControlError("arguments", errors.New("socket path must be absolute")))
	}
	if args[0] == "read-dump" {
		if !filepath.IsAbs(*dumpPath) {
			return writeFailure(output, newControlError("arguments", errors.New("absolute dump path is required")))
		}
		info, err := os.Stat(*dumpPath)
		if errors.Is(err, os.ErrNotExist) {
			return writeEnvelope(output, responseEnvelope{OK: true, Result: map[string]any{"metrics": nil}})
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return writeFailure(output, newControlError("read-dump", errors.New("invalid metrics dump")))
		}
		metrics.SetMetricsDumpFilePath(*dumpPath)
		if err := metrics.LoadMetricsFromDump(); err != nil {
			return writeFailure(output, newControlError("read-dump", err))
		}
		data, err := metrics.GetMetricsAsJSON()
		if err != nil {
			return writeFailure(output, newControlError("read-dump", err))
		}
		values, err := stringifyMetricNumbers(string(data))
		if err != nil {
			return writeFailure(output, newControlError("read-dump", err))
		}
		return writeEnvelope(output, responseEnvelope{OK: true, Result: map[string]any{"metrics": values}})
	}

	client, connection, err := dialManagementClient(*socketPath)
	if err != nil {
		return writeFailure(output, newControlError("connect", err))
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()

	var result any
	var controlErr *controlError
	switch args[0] {
	case "apply":
		if *configPath == "" {
			return writeFailure(output, newControlError("arguments", errors.New("config path is required")))
		}
		config, err := readConfig(*configPath)
		if err != nil {
			return writeFailure(output, newControlError("read-config", err))
		}
		result, controlErr = syncServer(ctx, client, config)
	case "stop":
		if *configPath != "" {
			return writeFailure(output, newControlError("arguments", errors.New("stop does not accept a config path")))
		}
		result, controlErr = stopServer(ctx, client)
	case "status":
		if *configPath != "" {
			return writeFailure(output, newControlError("arguments", errors.New("status does not accept a config path")))
		}
		result, controlErr = readStatus(ctx, client)
	default:
		return writeFailure(output, newControlError("arguments", fmt.Errorf("unsupported operation %q", args[0])))
	}
	if controlErr != nil {
		return writeFailure(output, controlErr)
	}
	return writeEnvelope(output, responseEnvelope{OK: true, Result: result})
}

func readConfig(path string) (*pb.ServerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}

	config := &pb.ServerConfig{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(contents, config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return config, nil
}

func writeFailure(output io.Writer, controlErr *controlError) error {
	if err := writeEnvelope(output, responseEnvelope{OK: false, Error: controlErr}); err != nil {
		return err
	}
	return controlErr
}

func writeEnvelope(output io.Writer, envelope responseEnvelope) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(envelope)
}
