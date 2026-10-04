package scenarios

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ACORE_SCENARIO_TESTS") == "" {
		fmt.Println("Skipping scenario tests. Set ACORE_SCENARIO_TESTS=1 to run.")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
