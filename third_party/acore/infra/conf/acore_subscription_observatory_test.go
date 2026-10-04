package conf

import (
	"testing"

	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/common/serial"
)

func TestBuildAutoAddsObservatoryWhenSubscriptionUsesObservatory(t *testing.T) {
	enabled := true
	cfg := &Config{
		Subscription: &SubscriptionConfig{
			Outbound: OutboundSubscriptionList{
				{
					Name:        "sub-a",
					URL:         "https://example.com/sub",
					Observatory: &SubscriptionObservatoryConfig{Enabled: &enabled},
				},
			},
		},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	observatoryType := serial.GetMessageType(&observatory.Config{})
	if !hasAppType(built.App, observatoryType) {
		t.Fatalf("expected app type %q to be added", observatoryType)
	}
}

func TestBuildDoesNotAddObservatoryWithoutSubscriptionObservatory(t *testing.T) {
	cfg := &Config{
		Subscription: &SubscriptionConfig{
			Outbound: OutboundSubscriptionList{
				{
					Name:     "sub-a",
					URL:      "https://example.com/sub",
					Interval: "1h",
				},
			},
		},
	}

	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("build failed: %v", err)
	}

	observatoryType := serial.GetMessageType(&observatory.Config{})
	if hasAppType(built.App, observatoryType) {
		t.Fatalf("did not expect app type %q to be added", observatoryType)
	}
}

func hasAppType(apps []*serial.TypedMessage, wantType string) bool {
	for _, app := range apps {
		if app == nil {
			continue
		}
		if app.GetType() == wantType {
			return true
		}
	}
	return false
}
