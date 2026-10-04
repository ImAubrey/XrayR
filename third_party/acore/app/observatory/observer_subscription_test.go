package observatory

import (
	"testing"
)

func TestUpdateSubscriptionObservationTracksChanges(t *testing.T) {
	observer := &Observer{}

	if changed := observer.UpdateSubscriptionObservation("", []string{"a"}, "https://example.com/test"); changed {
		t.Fatal("empty subscription name should not be treated as changed")
	}

	if changed := observer.UpdateSubscriptionObservation("sub-a", []string{"b", "a", "a"}, " https://example.com/test "); !changed {
		t.Fatal("first update should be treated as changed")
	}
	if got := observer.subjectSelectors(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected selectors after first update: %#v", got)
	}
	if got := observer.testURLForTag("a"); got != "https://example.com/test" {
		t.Fatalf("unexpected test url for tag a: %q", got)
	}

	if changed := observer.UpdateSubscriptionObservation("sub-a", []string{"a", "b"}, "https://example.com/test"); changed {
		t.Fatal("same normalized update should not be treated as changed")
	}

	if changed := observer.UpdateSubscriptionObservation("sub-a", []string{"a", "b"}, "https://example.com/next"); !changed {
		t.Fatal("test URL change should be treated as changed")
	}
	if got := observer.testURLForTag("b"); got != "https://example.com/next" {
		t.Fatalf("unexpected test url for tag b after update: %q", got)
	}

	if changed := observer.UpdateSubscriptionObservation("sub-a", nil, ""); !changed {
		t.Fatal("removing subscription observation should be treated as changed")
	}
	if changed := observer.UpdateSubscriptionObservation("sub-a", nil, ""); changed {
		t.Fatal("repeated removal should not be treated as changed")
	}
	if got := observer.subjectSelectors(); len(got) != 0 {
		t.Fatalf("expected no selectors after removal, got %#v", got)
	}
}
