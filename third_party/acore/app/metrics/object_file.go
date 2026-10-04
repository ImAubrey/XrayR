package metrics

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// readObjectFile reads a JSON/JSONC/YAML file into a generic map.
// It returns:
// - data: a non-nil map (empty when file missing/empty)
// - format: detectConfigFormat(path)
// - found: whether the file exists on disk
func readObjectFile(path string) (map[string]interface{}, string, bool, error) {
	format := detectConfigFormat(path)
	if path == "" {
		return map[string]interface{}{}, format, false, errors.New("path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, format, false, nil
		}
		return map[string]interface{}{}, format, false, err
	}
	body := strings.TrimSpace(string(raw))
	if body == "" {
		return map[string]interface{}{}, format, true, nil
	}

	var data map[string]interface{}
	switch format {
	case "yaml":
		if err := yaml.Unmarshal([]byte(body), &data); err != nil {
			return map[string]interface{}{}, format, true, err
		}
	case "jsonc":
		body = stripJSONComments(body)
		fallthrough
	case "json":
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			return map[string]interface{}{}, format, true, err
		}
	default:
		// Keep backward compatibility: treat unknown extensions as JSON.
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			return map[string]interface{}{}, format, true, err
		}
	}

	if data == nil {
		data = map[string]interface{}{}
	}
	return data, format, true, nil
}

func writeObjectFile(path string, data map[string]interface{}) error {
	if path == "" {
		return errors.New("path is empty")
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	if err := ensureParentDir(path); err != nil {
		return err
	}

	format := detectConfigFormat(path)
	var payload []byte
	var err error
	switch format {
	case "yaml":
		payload, err = yaml.Marshal(data)
		if err != nil {
			return err
		}
	default:
		payload, err = json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		payload = append(payload, '\n')
	}
	return os.WriteFile(path, payload, 0o644)
}
