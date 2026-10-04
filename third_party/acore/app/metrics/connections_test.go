package metrics

import (
	"testing"

	"github.com/ImAubrey/acore/features/conntrack"
)

func TestBuildMetadataCarriesJA4Fields(t *testing.T) {
	snap := conntrack.Snapshot{
		JA4:      "t13d1516h2_8daaf6152771_e5627efa2ab1",
		JA4Tag:   "source:ja4db",
		RouteTag: "route-tag",
	}

	meta := buildMetadata(snap)
	if meta.JA4 != snap.JA4 {
		t.Fatalf("unexpected JA4: got %q want %q", meta.JA4, snap.JA4)
	}
	if meta.JA4Tag != snap.JA4Tag {
		t.Fatalf("unexpected JA4 tag: got %q want %q", meta.JA4Tag, snap.JA4Tag)
	}
}

func TestBuildMetadataDoesNotInferJA4TagFromRouteTag(t *testing.T) {
	snap := conntrack.Snapshot{
		JA4:      "t13d1516h2_8daaf6152771_e5627efa2ab1",
		RouteTag: "ja4-rule",
	}

	meta := buildMetadata(snap)
	if meta.JA4Tag != "" {
		t.Fatalf("expected empty JA4 tag without explicit ja4_tag attribute, got %q", meta.JA4Tag)
	}
}
