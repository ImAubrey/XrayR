package metrics

import (
	"reflect"
	"strings"
	"testing"

	routercfg "github.com/ImAubrey/acore/app/router"
)

type fakeHandlerSelector struct {
	tags []string
}

func (s fakeHandlerSelector) Select(prefixes []string) []string {
	out := make([]string, 0)
	for _, rawTag := range s.tags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		for _, rawPrefix := range prefixes {
			prefix := strings.TrimSpace(rawPrefix)
			if prefix == "" {
				continue
			}
			if strings.HasPrefix(tag, prefix) {
				out = append(out, tag)
				break
			}
		}
	}
	return out
}

func TestResolveBalancerCandidates_PrefixSelectors(t *testing.T) {
	got := resolveBalancerCandidates(
		[]string{"w_"},
		nil,
		fakeHandlerSelector{tags: []string{
			"w_cn_lzh_cmh",
			"w_cn_lzh_cth",
			"w_cn_lzh_cml",
			"direct",
		}},
	)
	want := []string{
		"w_cn_lzh_cmh",
		"w_cn_lzh_cml",
		"w_cn_lzh_cth",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestResolveBalancerCandidates_NestedBalancerSelectors(t *testing.T) {
	balancerByTag := map[string]*routercfg.BalancingRule{
		"o_cn_home": {
			Tag:              "o_cn_home",
			OutboundSelector: []string{"w_"},
		},
		"o_cn_entry": {
			Tag:              "o_cn_entry",
			OutboundSelector: []string{"o_cn_home"},
		},
	}

	got := resolveBalancerCandidates(
		[]string{"o_cn_entry"},
		balancerByTag,
		fakeHandlerSelector{tags: []string{
			"w_cn_lzh_cmh",
			"w_cn_lzh_cth",
			"direct",
		}},
	)
	want := []string{"o_cn_entry"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestResolveBalancerCandidates_DedupAndTrim(t *testing.T) {
	got := resolveBalancerCandidates(
		[]string{" w_", "w_", "", "  "},
		nil,
		fakeHandlerSelector{tags: []string{
			"w_cn_lzh_cmh",
			" w_cn_lzh_cmh ",
			"w_cn_lzh_cth",
		}},
	)
	want := []string{"w_cn_lzh_cmh", "w_cn_lzh_cth"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestResolveBalancerCandidates_AvoidCycles(t *testing.T) {
	balancerByTag := map[string]*routercfg.BalancingRule{
		"A": {Tag: "A", OutboundSelector: []string{"B"}},
		"B": {Tag: "B", OutboundSelector: []string{"A"}},
	}

	got := resolveBalancerCandidates(
		[]string{"A"},
		balancerByTag,
		fakeHandlerSelector{tags: []string{"w_cn_lzh_cth"}},
	)
	want := []string{"A"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates mismatch\n got: %#v\nwant: %#v", got, want)
	}
}
