package router

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
	"golang.org/x/sync/singleflight"
)

type ja4HashPair struct {
	h1 uint64
	h2 uint64
}

type ja4TagSet struct {
	// Open-addressing hash table. Empty slot is {0,0}.
	// Collision probability with (h1,h2) pair is practically negligible.
	slots []ja4HashPair
	mask  uint64
	count int
}

const ja4TagSetCacheStatTTL = 5 * time.Millisecond

func (s *ja4TagSet) Contains(raw string) bool {
	fp, ok := normalizeJA4FingerprintFast(raw)
	if !ok {
		return false
	}
	return s.ContainsNormalized(fp)
}

func (s *ja4TagSet) ContainsNormalized(fp string) bool {
	if s == nil || len(s.slots) == 0 || s.mask == 0 {
		return false
	}
	key := hashJA4Pair(fp)
	idx := int(key.h1 & s.mask)
	step := int((key.h2 | 1) & s.mask)
	if step == 0 {
		step = 1
	}
	for probe := 0; probe < len(s.slots); probe++ {
		slot := s.slots[idx]
		if slot.h1 == 0 && slot.h2 == 0 {
			return false
		}
		if slot == key {
			return true
		}
		idx = (idx + step) & int(s.mask)
	}
	return false
}

func normalizeJA4FingerprintFast(raw string) (string, bool) {
	if len(raw) == ja4db.RecordLen && raw[10] == '_' && raw[23] == '_' {
		for i := 0; i < len(raw); i++ {
			ch := raw[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
				continue
			}
			return ja4db.NormalizeFingerprint(raw)
		}
		return raw, true
	}
	return ja4db.NormalizeFingerprint(raw)
}

func hashJA4Pair(fp string) ja4HashPair {
	// FNV-1a like twin hash (different offsets and primes) to avoid large lookup tables.
	const (
		off1 = uint64(14695981039346656037)
		off2 = uint64(1099511628211) ^ uint64(0x9e3779b97f4a7c15)
		p1   = uint64(1099511628211)
		p2   = uint64(14029467366897019727)
	)
	h1 := off1
	h2 := off2
	for i := 0; i < len(fp); i++ {
		b := uint64(fp[i])
		h1 ^= b
		h1 *= p1
		h2 ^= b
		h2 *= p2
	}
	// Reserve {0,0} as empty slot sentinel.
	if h1 == 0 && h2 == 0 {
		h1 = 1
	}
	return ja4HashPair{h1: h1, h2: h2}
}

func newJA4TagSetFromRecords(records []byte) (*ja4TagSet, error) {
	if len(records)%ja4db.RecordLen != 0 {
		return nil, os.ErrInvalid
	}
	n := len(records) / ja4db.RecordLen
	if n == 0 {
		return &ja4TagSet{}, nil
	}

	// Keep load factor <= 0.5 for short probe chains.
	capacity := 1
	for capacity < n*2 {
		capacity <<= 1
	}
	s := &ja4TagSet{
		slots: make([]ja4HashPair, capacity),
		mask:  uint64(capacity - 1),
	}

	for i := 0; i < n; i++ {
		start := i * ja4db.RecordLen
		key := hashJA4Pair(string(records[start : start+ja4db.RecordLen]))
		idx := int(key.h1 & s.mask)
		step := int((key.h2 | 1) & s.mask)
		if step == 0 {
			step = 1
		}
		for {
			slot := s.slots[idx]
			if slot.h1 == 0 && slot.h2 == 0 {
				s.slots[idx] = key
				s.count++
				break
			}
			if slot == key {
				// duplicate fingerprint
				break
			}
			idx = (idx + step) & int(s.mask)
		}
	}
	return s, nil
}

type ja4TagSetCacheEntry struct {
	modTimeUnixNano int64
	fileSize        int64
	loadedAt        time.Time
	set             *ja4TagSet
}

var ja4TagSetCache sync.Map // key: "<path>|<tag>" => *ja4TagSetCacheEntry
var ja4TagSetCacheLoadGroup singleflight.Group

func buildJA4UnlabeledRecords(path string) ([]byte, error) {
	allRecords, err := ja4db.ReadTagRecords(path, "all")
	if err != nil {
		return nil, err
	}
	if len(allRecords) == 0 {
		return []byte{}, nil
	}

	unlabeled := make(map[string]struct{}, len(allRecords)/ja4db.RecordLen)
	for i := 0; i < len(allRecords); i += ja4db.RecordLen {
		unlabeled[string(allRecords[i:i+ja4db.RecordLen])] = struct{}{}
	}

	tags, err := ja4db.ReadTagNames(path)
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if tag == "" || tag == "all" || tag == "!" {
			continue
		}
		records, err := ja4db.ReadTagRecords(path, tag)
		if err != nil {
			if err == ja4db.ErrTagNotFound {
				continue
			}
			return nil, err
		}
		for i := 0; i < len(records); i += ja4db.RecordLen {
			delete(unlabeled, string(records[i:i+ja4db.RecordLen]))
		}
	}

	if len(unlabeled) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, 0, len(unlabeled)*ja4db.RecordLen)
	for fp := range unlabeled {
		out = append(out, fp...)
	}
	return out, nil
}

func getJA4TagSet(file, tag string) (*ja4TagSet, error) {
	file = strings.TrimSpace(file)
	tag = strings.ToLower(strings.TrimSpace(tag))

	path := file
	if !filepath.IsAbs(path) {
		path = platform.GetAssetLocation(path)
	}
	path = filepath.Clean(path)
	cacheKey := strings.ToLower(path) + "|" + tag

	now := time.Now()
	if cached, ok := ja4TagSetCache.Load(cacheKey); ok {
		entry := cached.(*ja4TagSetCacheEntry)
		if entry.set != nil && now.Sub(entry.loadedAt) < ja4TagSetCacheStatTTL {
			return entry.set, nil
		}
	}

	loaded, err, _ := ja4TagSetCacheLoadGroup.Do(cacheKey, func() (interface{}, error) {
		now := time.Now()
		if cached, ok := ja4TagSetCache.Load(cacheKey); ok {
			entry := cached.(*ja4TagSetCacheEntry)
			if entry.set != nil && now.Sub(entry.loadedAt) < ja4TagSetCacheStatTTL {
				return entry.set, nil
			}
		}

		st, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		modTimeUnixNano := st.ModTime().UnixNano()
		fileSize := st.Size()

		if cached, ok := ja4TagSetCache.Load(cacheKey); ok {
			entry := cached.(*ja4TagSetCacheEntry)
			if entry.modTimeUnixNano == modTimeUnixNano && entry.fileSize == fileSize && entry.set != nil {
				ja4TagSetCache.Store(cacheKey, &ja4TagSetCacheEntry{
					modTimeUnixNano: modTimeUnixNano,
					fileSize:        fileSize,
					loadedAt:        now,
					set:             entry.set,
				})
				return entry.set, nil
			}
		}

		var records []byte
		var loadErr error
		if tag == "!" {
			records, loadErr = buildJA4UnlabeledRecords(path)
		} else {
			records, loadErr = ja4db.ReadTagRecords(path, tag)
		}
		if loadErr != nil {
			return nil, loadErr
		}

		set, buildErr := newJA4TagSetFromRecords(records)
		if buildErr != nil {
			return nil, buildErr
		}

		entry := &ja4TagSetCacheEntry{
			modTimeUnixNano: modTimeUnixNano,
			fileSize:        fileSize,
			loadedAt:        now,
			set:             set,
		}
		ja4TagSetCache.Store(cacheKey, entry)
		return set, nil
	})
	if err != nil {
		return nil, err
	}
	return loaded.(*ja4TagSet), nil
}
