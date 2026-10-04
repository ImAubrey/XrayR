package conf

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parsePreConKeep parses preConKeep from raw JSON.
// Returns (value, set, err). Value is int64(time.Duration) or -1 to disable.
func parsePreConKeep(raw json.RawMessage) (int64, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	v, err := parsePreConKeepValue(raw)
	if err != nil {
		return 0, false, err
	}
	return v, true, nil
}

func parsePreConKeepValue(raw json.RawMessage) (int64, error) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, err
	}
	switch value := v.(type) {
	case bool:
		if !value {
			return -1, nil
		}
		return 0, nil
	case float64:
		if value < 0 {
			return -1, nil
		}
		return int64(time.Duration(value * float64(time.Second))), nil
	case string:
		s := strings.TrimSpace(value)
		if s == "" {
			return 0, fmt.Errorf("invalid preConKeep: empty string")
		}
		if num, err := strconv.ParseFloat(s, 64); err == nil {
			if num < 0 {
				return -1, nil
			}
			return int64(time.Duration(num * float64(time.Second))), nil
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return 0, err
		}
		return int64(dur), nil
	default:
		if v == nil {
			return 0, fmt.Errorf("invalid preConKeep: null")
		}
		return 0, fmt.Errorf("invalid preConKeep: %T", v)
	}
}

// normalizePreConKeep converts preConKeep into a numeric JSON value for proto structs.
func normalizePreConKeep(raw json.RawMessage) (json.RawMessage, bool, error) {
	if len(raw) == 0 {
		return raw, false, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, false, nil
	}
	valRaw, ok := obj["preConKeep"]
	if !ok {
		return raw, false, nil
	}
	v, err := parsePreConKeepValue(valRaw)
	if err != nil {
		return nil, false, err
	}
	valJSON, err := json.Marshal(v)
	if err != nil {
		return nil, false, err
	}
	obj["preConKeep"] = valJSON
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}
