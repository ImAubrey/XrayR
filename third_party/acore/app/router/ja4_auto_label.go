package router

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
	"golang.org/x/sync/singleflight"
)

type ja4AutoTagCacheEntry struct {
	modTimeUnixNano int64
	fileSize        int64
	tags            []string
}

var ja4AutoTagCache sync.Map // key: lower(abs path) => *ja4AutoTagCacheEntry
var ja4AutoTagLoadGroup singleflight.Group

func resolveJA4DBPath(file string) string {
	path := strings.TrimSpace(file)
	if path == "" {
		return ""
	}
	if !filepath.IsAbs(path) {
		path = platform.GetAssetLocation(path)
	}
	return filepath.Clean(path)
}

func preferredJA4AutoTags(file string) ([]string, error) {
	path := resolveJA4DBPath(file)
	if path == "" {
		return nil, os.ErrInvalid
	}
	key := strings.ToLower(path)

	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	modTime := st.ModTime().UnixNano()
	size := st.Size()

	if cached, ok := ja4AutoTagCache.Load(key); ok {
		entry := cached.(*ja4AutoTagCacheEntry)
		if entry.modTimeUnixNano == modTime && entry.fileSize == size && len(entry.tags) > 0 {
			return append([]string(nil), entry.tags...), nil
		}
	}

	loaded, err, _ := ja4AutoTagLoadGroup.Do(key, func() (interface{}, error) {
		st, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		modTime := st.ModTime().UnixNano()
		size := st.Size()

		if cached, ok := ja4AutoTagCache.Load(key); ok {
			entry := cached.(*ja4AutoTagCacheEntry)
			if entry.modTimeUnixNano == modTime && entry.fileSize == size && len(entry.tags) > 0 {
				return append([]string(nil), entry.tags...), nil
			}
		}

		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if !ja4db.IsBinary(body) {
			return nil, ja4db.ErrNotBinary
		}
		if len(body) < len(ja4db.Magic)+2+4 {
			return nil, os.ErrInvalid
		}
		p := len(ja4db.Magic)
		version := binary.BigEndian.Uint16(body[p : p+2])
		p += 2
		if version != ja4db.Version {
			return nil, os.ErrInvalid
		}
		tagCount := int(binary.BigEndian.Uint32(body[p : p+4]))
		p += 4

		tags := make([]string, 0, tagCount)
		for i := 0; i < tagCount; i++ {
			if p+2 > len(body) {
				return nil, os.ErrInvalid
			}
			nameLen := int(binary.BigEndian.Uint16(body[p : p+2]))
			p += 2
			if nameLen < 0 || p+nameLen+8+4 > len(body) {
				return nil, os.ErrInvalid
			}
			name := strings.TrimSpace(strings.ToLower(string(body[p : p+nameLen])))
			p += nameLen
			p += 8 // offset
			p += 4 // count
			if name == "" || name == "all" {
				continue
			}
			if !isPreferredAutoLabelTag(name) {
				continue
			}
			tags = append(tags, name)
		}

		sort.Slice(tags, func(i, j int) bool {
			li := tags[i]
			lj := tags[j]
			ri := ja4AutoLabelRank(li)
			rj := ja4AutoLabelRank(lj)
			if ri != rj {
				return ri < rj
			}
			if len(li) != len(lj) {
				return len(li) > len(lj) // prefer more specific tags
			}
			return li < lj
		})

		ja4AutoTagCache.Store(key, &ja4AutoTagCacheEntry{
			modTimeUnixNano: modTime,
			fileSize:        size,
			tags:            append([]string(nil), tags...),
		})
		return tags, nil
	})
	if err != nil {
		return nil, err
	}
	return append([]string(nil), loaded.([]string)...), nil
}

func isPreferredAutoLabelTag(tag string) bool {
	switch {
	case strings.HasPrefix(tag, "ua:family:"):
		return true
	case strings.HasPrefix(tag, "app:"):
		return true
	case strings.HasPrefix(tag, "client:"):
		return true
	case strings.HasPrefix(tag, "library:"):
		return true
	case strings.HasPrefix(tag, "device:"):
		return true
	case strings.HasPrefix(tag, "os:"):
		return true
	case strings.HasPrefix(tag, "source:"):
		return true
	default:
		return false
	}
}

func isDetailedJA4DisplayTag(tag string) bool {
	normalized := normalizeJA4DisplayTagForRank(tag)
	switch {
	case strings.HasPrefix(normalized, "ua:family:"):
		return true
	case strings.HasPrefix(normalized, "app:"):
		return true
	case strings.HasPrefix(normalized, "client:"):
		return true
	case strings.HasPrefix(normalized, "library:"):
		return true
	case strings.HasPrefix(normalized, "device:"):
		return true
	case strings.HasPrefix(normalized, "os:"):
		return true
	default:
		return false
	}
}

func normalizeJA4DisplayTagForRank(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

func shouldPreferJA4DisplayTag(candidate string, current string) bool {
	candidate = strings.TrimSpace(candidate)
	current = strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	candidateRank := ja4DisplayTagRank(candidate)
	currentRank := ja4DisplayTagRank(current)
	if candidateRank != currentRank {
		return candidateRank < currentRank
	}
	if len(candidate) != len(current) {
		return len(candidate) > len(current)
	}
	return candidate < current
}

func ja4DisplayTagRank(tag string) int {
	normalized := normalizeJA4DisplayTagForRank(tag)
	switch {
	case strings.HasPrefix(normalized, "ua:family:") && strings.Contains(normalized, "-"):
		return 0
	case strings.HasPrefix(normalized, "ua:family:") && strings.Contains(normalized, ":major:"):
		return 4
	case strings.HasPrefix(normalized, "ua:family:"):
		return 5
	case strings.HasPrefix(normalized, "app:") && strings.Contains(normalized, ":major:"):
		return 10
	case strings.HasPrefix(normalized, "app:"):
		return 11
	case strings.HasPrefix(normalized, "client:"):
		return 12
	case strings.HasPrefix(normalized, "library:"):
		return 13
	case strings.HasPrefix(normalized, "device:"):
		return 14
	case strings.HasPrefix(normalized, "os:"):
		return 15
	case strings.HasPrefix(normalized, "threat:"):
		return 30
	case strings.HasPrefix(normalized, "label:"):
		return 31
	case normalized != "" && !strings.Contains(normalized, ":"):
		return 32
	case strings.HasPrefix(normalized, "source:"):
		return 90
	default:
		return 100
	}
}

func ja4AutoLabelRank(tag string) int {
	return ja4DisplayTagRank(tag)
}
