package router

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ImAubrey/acore/common/ja4db"
	"github.com/ImAubrey/acore/common/platform"
)

const (
	benchJA4Tag      = "malware"
	benchJA4ItemSize = 20000
)

func benchJA4Fingerprints(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("t13d1516h2_%012x_%012x", uint64(i), uint64(i)*0x9e3779b1))
	}
	return out
}

func benchJA4TagSet(tb testing.TB, n int) (*ja4TagSet, []string) {
	tb.Helper()
	fingerprints := benchJA4Fingerprints(n)
	records := make([]byte, 0, len(fingerprints)*ja4db.RecordLen)
	for _, fp := range fingerprints {
		records = append(records, fp...)
	}
	set, err := newJA4TagSetFromRecords(records)
	if err != nil {
		tb.Fatalf("newJA4TagSetFromRecords failed: %v", err)
	}
	return set, fingerprints
}

func writeBenchJA4DB(tb testing.TB, dir string, file string, tag string, fingerprints []string) string {
	tb.Helper()
	var builder strings.Builder
	builder.Grow(len(fingerprints) * (ja4db.RecordLen + len(tag) + 2))
	for _, fp := range fingerprints {
		builder.WriteString(fp)
		builder.WriteByte(',')
		builder.WriteString(tag)
		builder.WriteByte('\n')
	}

	bin, err := ja4db.Compile([]byte(builder.String()))
	if err != nil {
		tb.Fatalf("ja4db.Compile failed: %v", err)
	}

	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, bin, 0o644); err != nil {
		tb.Fatalf("write ja4 db failed: %v", err)
	}
	return path
}

func BenchmarkJA4TagSetContainsHit(b *testing.B) {
	set, fingerprints := benchJA4TagSet(b, benchJA4ItemSize)
	target := fingerprints[len(fingerprints)/2]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !set.Contains(target) {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkJA4TagSetContainsHitNeedsNormalize(b *testing.B) {
	set, fingerprints := benchJA4TagSet(b, benchJA4ItemSize)
	target := strings.ToUpper(fingerprints[len(fingerprints)/2])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !set.Contains(target) {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkJA4TagSetContainsMiss(b *testing.B) {
	set, _ := benchJA4TagSet(b, benchJA4ItemSize)
	miss := "t13d1516h2_ffffffffffff_ffffffffffff"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if set.Contains(miss) {
			b.Fatal("expected miss")
		}
	}
}

func BenchmarkAttributeMatcherJA4DatabaseHit(b *testing.B) {
	ja4TagSetCache = sync.Map{}
	fingerprints := benchJA4Fingerprints(benchJA4ItemSize)
	assetDir := b.TempDir()
	_ = writeBenchJA4DB(b, assetDir, "ja4-bench.db", benchJA4Tag, fingerprints)
	b.Setenv(platform.AssetLocation, assetDir)

	matcher, err := NewAttributeMatcher(map[string]string{
		"ja4": EncodeJA4DBAttributeValue("ja4-bench.db", benchJA4Tag),
	})
	if err != nil {
		b.Fatalf("NewAttributeMatcher failed: %v", err)
	}

	attrs := map[string]string{"ja4": fingerprints[len(fingerprints)/2]}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !matcher.Match(attrs) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkAttributeMatcherJA4DatabaseHitNeedsNormalize(b *testing.B) {
	ja4TagSetCache = sync.Map{}
	fingerprints := benchJA4Fingerprints(benchJA4ItemSize)
	assetDir := b.TempDir()
	_ = writeBenchJA4DB(b, assetDir, "ja4-bench.db", benchJA4Tag, fingerprints)
	b.Setenv(platform.AssetLocation, assetDir)

	matcher, err := NewAttributeMatcher(map[string]string{
		"ja4": EncodeJA4DBAttributeValue("ja4-bench.db", benchJA4Tag),
	})
	if err != nil {
		b.Fatalf("NewAttributeMatcher failed: %v", err)
	}

	attrs := map[string]string{"ja4": strings.ToUpper(fingerprints[len(fingerprints)/2])}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !matcher.Match(attrs) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkAttributeMatcherJA4RegexHit(b *testing.B) {
	fingerprints := benchJA4Fingerprints(benchJA4ItemSize)
	target := fingerprints[len(fingerprints)/2]

	matcher, err := NewAttributeMatcher(map[string]string{
		"ja4": "^" + target + "$",
	})
	if err != nil {
		b.Fatalf("NewAttributeMatcher failed: %v", err)
	}

	attrs := map[string]string{"ja4": target}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !matcher.Match(attrs) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkGetJA4TagSetCacheHit(b *testing.B) {
	ja4TagSetCache = sync.Map{}
	fingerprints := benchJA4Fingerprints(benchJA4ItemSize)
	path := writeBenchJA4DB(b, b.TempDir(), "ja4-bench.db", benchJA4Tag, fingerprints)
	target := fingerprints[len(fingerprints)/2]

	primed, err := getJA4TagSet(path, benchJA4Tag)
	if err != nil {
		b.Fatalf("getJA4TagSet prime failed: %v", err)
	}
	if !primed.Contains(target) {
		b.Fatal("expected hit after priming")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set, err := getJA4TagSet(path, benchJA4Tag)
		if err != nil {
			b.Fatalf("getJA4TagSet failed: %v", err)
		}
		if !set.Contains(target) {
			b.Fatal("expected hit")
		}
	}
}
