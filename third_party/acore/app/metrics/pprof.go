package metrics

import (
	_ "net/http/pprof"
)

func registerPprofRoutesIfEnabled() {
	// net/http/pprof registers handlers on DefaultServeMux in package init.
	// Access control is enforced in wrapMetricsHandler.
}
