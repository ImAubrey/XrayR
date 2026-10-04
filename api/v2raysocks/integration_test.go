package v2raysocks_test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACORE_BACKEND_RUN_INTEGRATION_TESTS") != "1" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
