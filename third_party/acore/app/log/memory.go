package log

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	clog "github.com/ImAubrey/acore/common/log"
)

type MemoryEntry struct {
	ID   int64
	Line string
}

const defaultMemoryCapacity = 2000

var memoryCap = int64(defaultMemoryCapacity)
var memoryMu sync.RWMutex
var memoryEntries []MemoryEntry
var memoryNextID int64
var memoryLevelOverride int32

func init() {
	if raw := os.Getenv("LOG_MEMORY_LINES"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			atomic.StoreInt64(&memoryCap, int64(v))
		}
	}
}

func SetMemoryLogLevel(level clog.Severity) {
	if level <= clog.Severity_Unknown {
		atomic.StoreInt32(&memoryLevelOverride, 0)
		return
	}
	atomic.StoreInt32(&memoryLevelOverride, int32(level))
}

func ClearMemoryLogLevelOverride() {
	atomic.StoreInt32(&memoryLevelOverride, 0)
}

func MemoryLogLevelOverride() (clog.Severity, bool) {
	level := clog.Severity(atomic.LoadInt32(&memoryLevelOverride))
	if level <= clog.Severity_Unknown {
		return 0, false
	}
	return level, true
}

func MemoryLogDebugOverrideEnabled() bool {
	level, ok := MemoryLogLevelOverride()
	return ok && level >= clog.Severity_Debug
}

func recordMemoryMessage(msg clog.Message) {
	if msg == nil {
		return
	}
	line := msg.String()
	if line == "" {
		return
	}
	recordMemoryLine(formatMemoryLine(line))
}

func recordMemoryLine(line string) {
	if line == "" {
		return
	}
	entry := MemoryEntry{
		ID:   atomic.AddInt64(&memoryNextID, 1),
		Line: line,
	}
	capacity := int(atomic.LoadInt64(&memoryCap))
	if capacity <= 0 {
		return
	}

	memoryMu.Lock()
	memoryEntries = append(memoryEntries, entry)
	if len(memoryEntries) > capacity {
		memoryEntries = memoryEntries[len(memoryEntries)-capacity:]
	}
	memoryMu.Unlock()
}

func MemoryTail(limit int) []MemoryEntry {
	if limit <= 0 {
		limit = defaultMemoryCapacity
	}
	memoryMu.RLock()
	defer memoryMu.RUnlock()
	if len(memoryEntries) == 0 {
		return nil
	}
	if limit > len(memoryEntries) {
		limit = len(memoryEntries)
	}
	start := len(memoryEntries) - limit
	out := make([]MemoryEntry, limit)
	copy(out, memoryEntries[start:])
	return out
}

func MemorySince(id int64) []MemoryEntry {
	if id <= 0 {
		return MemoryTail(defaultMemoryCapacity)
	}
	memoryMu.RLock()
	defer memoryMu.RUnlock()
	if len(memoryEntries) == 0 {
		return nil
	}
	idx := 0
	for idx < len(memoryEntries) && memoryEntries[idx].ID <= id {
		idx++
	}
	if idx >= len(memoryEntries) {
		return nil
	}
	out := make([]MemoryEntry, len(memoryEntries)-idx)
	copy(out, memoryEntries[idx:])
	return out
}

func formatMemoryLine(line string) string {
	ts := time.Now().Format("2006/01/02 15:04:05.000000")
	return ts + " " + line
}
