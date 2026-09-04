package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func stringifyMetricNumbers(raw string) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()

	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode metrics JSON: %w", err)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return nil, err
	}

	converted, err := stringifyNumbers(decoded)
	if err != nil {
		return nil, err
	}
	metrics, ok := converted.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metrics JSON root must be an object")
	}
	return metrics, nil
}

func ensureJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing metrics JSON: %w", err)
	}
	return fmt.Errorf("metrics JSON contains multiple values")
}

func stringifyNumbers(value any) (any, error) {
	switch typed := value.(type) {
	case json.Number:
		if _, err := strconv.ParseInt(typed.String(), 10, 64); err != nil {
			return nil, fmt.Errorf("metric value %q is not an int64: %w", typed.String(), err)
		}
		return typed.String(), nil
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, nested := range typed {
			converted, err := stringifyNumbers(nested)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for index, nested := range typed {
			converted, err := stringifyNumbers(nested)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case nil, bool, string:
		return typed, nil
	default:
		return nil, fmt.Errorf("metrics JSON contains unsupported value %T", typed)
	}
}
