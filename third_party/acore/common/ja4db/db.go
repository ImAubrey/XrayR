package ja4db

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	stdErrors "errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	Magic     = "XJ4DB01\n"
	Version   = uint16(1)
	RecordLen = 36
)

var (
	ErrNotBinary   = stdErrors.New("ja4db: not binary")
	ErrTagNotFound = stdErrors.New("ja4db: tag not found")
)

var magicBytes = []byte(Magic)

func IsBinary(raw []byte) bool {
	return len(raw) >= len(magicBytes) && bytes.Equal(raw[:len(magicBytes)], magicBytes)
}

func NormalizeTag(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func NormalizeFingerprint(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) != RecordLen {
		return "", false
	}
	if s[10] != '_' || s[23] != '_' {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}
		return "", false
	}
	return s, true
}

func Compile(raw []byte) ([]byte, error) {
	if IsBinary(raw) {
		if _, err := readTagRecordsFromBinaryBytes(raw, "all"); err == nil || stdErrors.Is(err, ErrTagNotFound) {
			return raw, nil
		}
	}

	sets := make(map[string]map[string]struct{})
	add := func(tag, fp string) {
		tag = NormalizeTag(tag)
		if tag == "" {
			return
		}
		tagSet := sets[tag]
		if tagSet == nil {
			tagSet = make(map[string]struct{})
			sets[tag] = tagSet
		}
		tagSet[fp] = struct{}{}
	}

	err := parseEntries(raw, func(fp string, tags []string) {
		// "all" always contains all fingerprints, useful for bulk matching.
		add("all", fp)
		if len(tags) == 0 {
			return
		}
		for _, tag := range tags {
			add(tag, fp)
		}
	})
	if err != nil {
		return nil, err
	}
	if len(sets) == 0 {
		return nil, fmt.Errorf("ja4db: no valid records found")
	}

	tagRecords := make(map[string][]string, len(sets))
	for tag, set := range sets {
		values := make([]string, 0, len(set))
		for fp := range set {
			values = append(values, fp)
		}
		sort.Strings(values)
		tagRecords[tag] = values
	}

	return encodeBinary(tagRecords)
}

// PrepareForSubscription validates JA4 subscription payload bytes.
// sourceType supports:
// - "auto" (default): require already-compiled binary JA4 DB
// - "db": require already-compiled binary JA4 DB
// - "json": unsupported in runtime (local JSON/TXT -> DB conversion removed)
func PrepareForSubscription(raw []byte, sourceType string) ([]byte, error) {
	mode := strings.ToLower(strings.TrimSpace(sourceType))
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "auto", "db":
		if !IsBinary(raw) {
			return nil, fmt.Errorf("ja4db: sourceType %s expects compiled binary ja4 db payload", mode)
		}
		if _, err := readTagRecordsFromBinaryBytes(raw, "all"); err != nil && !stdErrors.Is(err, ErrTagNotFound) {
			return nil, err
		}
		return raw, nil
	case "json":
		return nil, fmt.Errorf("ja4db: sourceType json is unsupported in runtime; precompile to binary ja4 db")
	default:
		return nil, fmt.Errorf("ja4db: unsupported sourceType %q", sourceType)
	}
}

func CollectTag(raw []byte, tag string) ([]string, error) {
	tag = NormalizeTag(tag)
	if tag == "" {
		return nil, fmt.Errorf("ja4db: empty tag")
	}
	if IsBinary(raw) {
		records, err := readTagRecordsFromBinaryBytes(raw, tag)
		if err != nil {
			return nil, err
		}
		return recordsToStrings(records), nil
	}

	seen := make(map[string]struct{})
	err := parseEntries(raw, func(fp string, tags []string) {
		if tag == "all" {
			seen[fp] = struct{}{}
			return
		}
		for _, t := range tags {
			if NormalizeTag(t) == tag {
				seen[fp] = struct{}{}
				return
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrTagNotFound, tag)
	}
	values := make([]string, 0, len(seen))
	for fp := range seen {
		values = append(values, fp)
	}
	sort.Strings(values)
	return values, nil
}

func ReadTagRecords(path string, tag string) ([]byte, error) {
	tag = NormalizeTag(tag)
	if tag == "" {
		return nil, fmt.Errorf("ja4db: empty tag")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, len(magicBytes)+2+4)
	if _, err := io.ReadFull(f, header); err != nil {
		if stdErrors.Is(err, io.EOF) || stdErrors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotBinary
		}
		return nil, err
	}
	if !bytes.Equal(header[:len(magicBytes)], magicBytes) {
		return nil, ErrNotBinary
	}
	version := binary.BigEndian.Uint16(header[len(magicBytes) : len(magicBytes)+2])
	if version != Version {
		return nil, fmt.Errorf("ja4db: unsupported version %d", version)
	}
	tagCount := binary.BigEndian.Uint32(header[len(magicBytes)+2:])

	var foundOffset uint64
	var foundCount uint32
	found := false
	for i := uint32(0); i < tagCount; i++ {
		tagName, offset, count, err := readIndexEntry(f)
		if err != nil {
			return nil, err
		}
		if NormalizeTag(tagName) == tag {
			found = true
			foundOffset = offset
			foundCount = count
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrTagNotFound, tag)
	}
	size := int(foundCount) * RecordLen
	if size == 0 {
		return []byte{}, nil
	}
	records := make([]byte, size)
	if _, err := f.ReadAt(records, int64(foundOffset)); err != nil {
		return nil, err
	}
	return records, nil
}

func ReadTagValues(path string, tag string) ([]string, error) {
	records, err := ReadTagRecords(path, tag)
	if err != nil {
		return nil, err
	}
	return recordsToStrings(records), nil
}

func ReadTagNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, len(magicBytes)+2+4)
	if _, err := io.ReadFull(f, header); err != nil {
		if stdErrors.Is(err, io.EOF) || stdErrors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotBinary
		}
		return nil, err
	}
	if !bytes.Equal(header[:len(magicBytes)], magicBytes) {
		return nil, ErrNotBinary
	}
	version := binary.BigEndian.Uint16(header[len(magicBytes) : len(magicBytes)+2])
	if version != Version {
		return nil, fmt.Errorf("ja4db: unsupported version %d", version)
	}
	tagCount := binary.BigEndian.Uint32(header[len(magicBytes)+2:])

	seen := make(map[string]struct{}, tagCount)
	names := make([]string, 0, tagCount)
	for i := uint32(0); i < tagCount; i++ {
		tagName, _, _, err := readIndexEntry(f)
		if err != nil {
			return nil, err
		}
		norm := NormalizeTag(tagName)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		names = append(names, norm)
	}
	return names, nil
}

func parseEntries(raw []byte, sink func(fp string, tags []string)) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return fmt.Errorf("ja4db: empty content")
	}
	switch raw[0] {
	case '{', '[':
		return parseJSONEntries(raw, sink)
	default:
		return parseTextEntries(raw, sink)
	}
}

func parseTextEntries(raw []byte, sink func(fp string, tags []string)) error {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == '{' || line[0] == '[' {
			if err := parseJSONEntries([]byte(line), sink); err != nil {
				return err
			}
			continue
		}
		fields := splitFields(line)
		if len(fields) == 0 {
			continue
		}
		fp, ok := NormalizeFingerprint(fields[0])
		if !ok {
			continue
		}
		tags := normalizeTags(fields[1:])
		sink(fp, tags)
	}
	return scanner.Err()
}

func parseJSONEntries(raw []byte, sink func(fp string, tags []string)) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return fmt.Errorf("ja4db: invalid json root")
	}
	switch d {
	case '[':
		for dec.More() {
			var item any
			if err := dec.Decode(&item); err != nil {
				return err
			}
			consumeJSONItem(item, "", sink)
		}
		_, err := dec.Token()
		return err
	case '{':
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyToken.(string)
			var value any
			if err := dec.Decode(&value); err != nil {
				return err
			}
			consumeJSONObjectField(key, value, sink)
		}
		_, err := dec.Token()
		return err
	default:
		return fmt.Errorf("ja4db: invalid json root token")
	}
}

func consumeJSONObjectField(key string, value any, sink func(fp string, tags []string)) {
	if looksLikeArrayOfFingerprints(value) && isLikelyTagKey(key) {
		for _, fp := range toStringSlice(value) {
			if normalized, ok := NormalizeFingerprint(fp); ok {
				sink(normalized, []string{key})
			}
		}
		return
	}

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			consumeJSONItem(item, key, sink)
		}
	case map[string]any, string:
		consumeJSONItem(v, key, sink)
	default:
	}
}

func consumeJSONItem(item any, fallbackTag string, sink func(fp string, tags []string)) {
	switch v := item.(type) {
	case string:
		if fp, ok := NormalizeFingerprint(v); ok {
			tags := []string{}
			if isLikelyTagKey(fallbackTag) {
				tags = append(tags, fallbackTag)
			}
			sink(fp, normalizeTags(tags))
		}
	case map[string]any:
		fp, ok := extractFingerprint(v)
		if !ok {
			// nested tag map: {"malware": ["..."], "benign": ["..."]}
			for key, value := range v {
				consumeJSONObjectField(key, value, sink)
			}
			return
		}
		tags := extractTags(v)
		if len(tags) == 0 && isLikelyTagKey(fallbackTag) {
			tags = append(tags, fallbackTag)
		}
		sink(fp, normalizeTags(tags))
	case []any:
		for _, sub := range v {
			consumeJSONItem(sub, fallbackTag, sink)
		}
	default:
	}
}

func extractFingerprint(m map[string]any) (string, bool) {
	for _, key := range []string{"ja4", "fingerprint", "fp", "hash", "value", "id"} {
		v, ok := m[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if fp, ok := NormalizeFingerprint(s); ok {
			return fp, true
		}
	}
	return "", false
}

func extractTags(m map[string]any) []string {
	out := make([]string, 0, 4)
	collect := func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, item := range t {
				if s, ok := item.(string); ok {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, t...)
		}
	}
	for _, key := range []string{"tags", "tag", "category", "categories", "label", "labels", "family"} {
		if v, ok := m[key]; ok {
			collect(v)
		}
	}
	return out
}

func normalizeTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		n := NormalizeTag(tag)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func splitFields(line string) []string {
	parts := strings.Split(line, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		field := strings.TrimSpace(part)
		field = strings.Trim(field, "\"")
		if field == "" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func looksLikeArrayOfFingerprints(v any) bool {
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return false
	}
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return false
		}
		if _, ok := NormalizeFingerprint(s); !ok {
			return false
		}
	}
	return true
}

func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, s)
	}
	return out
}

func isLikelyTagKey(key string) bool {
	key = NormalizeTag(key)
	switch key {
	case "", "meta", "metadata", "version", "updated", "updated_at", "source", "sources", "name", "description":
		return false
	default:
		return true
	}
}

func encodeBinary(tagRecords map[string][]string) ([]byte, error) {
	tags := make([]string, 0, len(tagRecords))
	for tag := range tagRecords {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	headerSize := len(magicBytes) + 2 + 4
	indexSize := 0
	for _, tag := range tags {
		indexSize += 2 + len(tag) + 8 + 4
	}
	dataOffset := uint64(headerSize + indexSize)

	type indexMeta struct {
		offset uint64
		count  uint32
	}
	index := make(map[string]indexMeta, len(tags))
	offset := dataOffset
	for _, tag := range tags {
		records := tagRecords[tag]
		index[tag] = indexMeta{
			offset: offset,
			count:  uint32(len(records)),
		}
		offset += uint64(len(records) * RecordLen)
	}

	buf := bytes.NewBuffer(make([]byte, 0, int(offset)))
	buf.Write(magicBytes)
	if err := binary.Write(buf, binary.BigEndian, Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(len(tags))); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		tagBytes := []byte(tag)
		if len(tagBytes) > 0xffff {
			return nil, fmt.Errorf("ja4db: tag too long: %s", tag)
		}
		meta := index[tag]
		if err := binary.Write(buf, binary.BigEndian, uint16(len(tagBytes))); err != nil {
			return nil, err
		}
		if _, err := buf.Write(tagBytes); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, meta.offset); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, meta.count); err != nil {
			return nil, err
		}
	}
	for _, tag := range tags {
		for _, fp := range tagRecords[tag] {
			if len(fp) != RecordLen {
				return nil, fmt.Errorf("ja4db: invalid fingerprint length: %s", fp)
			}
			if _, err := buf.WriteString(fp); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func readIndexEntry(r io.Reader) (string, uint64, uint32, error) {
	var nameLen uint16
	if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
		return "", 0, 0, err
	}
	nameBytes := make([]byte, int(nameLen))
	if _, err := io.ReadFull(r, nameBytes); err != nil {
		return "", 0, 0, err
	}
	var offset uint64
	if err := binary.Read(r, binary.BigEndian, &offset); err != nil {
		return "", 0, 0, err
	}
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return "", 0, 0, err
	}
	return string(nameBytes), offset, count, nil
}

func recordsToStrings(records []byte) []string {
	if len(records) == 0 {
		return nil
	}
	count := len(records) / RecordLen
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		start := i * RecordLen
		values = append(values, string(records[start:start+RecordLen]))
	}
	return values
}

func readTagRecordsFromBinaryBytes(raw []byte, tag string) ([]byte, error) {
	tag = NormalizeTag(tag)
	if tag == "" {
		return nil, fmt.Errorf("ja4db: empty tag")
	}
	reader := bytes.NewReader(raw)
	header := make([]byte, len(magicBytes)+2+4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, ErrNotBinary
	}
	if !bytes.Equal(header[:len(magicBytes)], magicBytes) {
		return nil, ErrNotBinary
	}
	version := binary.BigEndian.Uint16(header[len(magicBytes) : len(magicBytes)+2])
	if version != Version {
		return nil, fmt.Errorf("ja4db: unsupported version %d", version)
	}
	tagCount := binary.BigEndian.Uint32(header[len(magicBytes)+2:])

	var foundOffset uint64
	var foundCount uint32
	found := false
	for i := uint32(0); i < tagCount; i++ {
		name, offset, count, err := readIndexEntry(reader)
		if err != nil {
			return nil, err
		}
		if NormalizeTag(name) == tag {
			found = true
			foundOffset = offset
			foundCount = count
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrTagNotFound, tag)
	}
	size := int(foundCount) * RecordLen
	if size == 0 {
		return []byte{}, nil
	}
	if int(foundOffset)+size > len(raw) {
		return nil, fmt.Errorf("ja4db: invalid index bounds")
	}
	out := make([]byte, size)
	copy(out, raw[int(foundOffset):int(foundOffset)+size])
	return out, nil
}
