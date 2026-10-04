package router

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ImAubrey/acore/common/ja4db"
)

func TestGetJA4TagSetAbsolutePathCacheHit(t *testing.T) {
	ja4TagSetCache = sync.Map{}
	dbPath := filepath.Join(t.TempDir(), "ja4.db")
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"

	bin, err := ja4db.Compile([]byte(fp + ",malware\n"))
	if err != nil {
		t.Fatalf("compile ja4 db: %v", err)
	}
	if err := os.WriteFile(dbPath, bin, 0o644); err != nil {
		t.Fatalf("write ja4 db: %v", err)
	}

	first, err := getJA4TagSet(dbPath, "malware")
	if err != nil {
		t.Fatalf("first getJA4TagSet failed: %v", err)
	}
	if !first.Contains(fp) {
		t.Fatal("expected first matcher to contain fingerprint")
	}

	second, err := getJA4TagSet(dbPath, "malware")
	if err != nil {
		t.Fatalf("second getJA4TagSet failed: %v", err)
	}
	if !second.Contains(fp) {
		t.Fatal("expected second matcher to contain fingerprint")
	}
}

func TestNormalizeJA4FingerprintFast(t *testing.T) {
	raw := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	got, ok := normalizeJA4FingerprintFast(raw)
	if !ok {
		t.Fatal("expected normalized JA4 to pass fast path")
	}
	if got != raw {
		t.Fatalf("unexpected normalized value: got=%q want=%q", got, raw)
	}

	upper := strings.ToUpper(raw)
	got, ok = normalizeJA4FingerprintFast(upper)
	if !ok {
		t.Fatal("expected uppercase JA4 to be normalized by fallback")
	}
	if got != raw {
		t.Fatalf("unexpected fallback normalized value: got=%q want=%q", got, raw)
	}
}

func TestJA4TagSetContainsNormalized(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	set, err := newJA4TagSetFromRecords([]byte(fp))
	if err != nil {
		t.Fatalf("newJA4TagSetFromRecords failed: %v", err)
	}
	if !set.ContainsNormalized(fp) {
		t.Fatal("expected normalized contains to match")
	}
	if set.ContainsNormalized("t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb") {
		t.Fatal("expected normalized contains to miss unknown fingerprint")
	}
}
