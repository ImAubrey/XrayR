package conntrack

import (
	"testing"
	"time"

	"github.com/ImAubrey/acore/common/net"
)

func TestManagerCountsConnectionsBySourceAndDestination(t *testing.T) {
	mgr := NewManager()

	conn1 := mgr.NewConnection(Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	})
	conn2 := mgr.NewConnection(Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12002),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.3"), 443),
	})

	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeSourceIP, "203.0.113.10", "", 0); got != 2 {
		t.Fatalf("source counter = %d, want 2", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeDestinationIP, "", "198.51.100.2", 0); got != 1 {
		t.Fatalf("destination counter = %d, want 1", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeSourceDestinationIP, "203.0.113.10", "198.51.100.3", 0); got != 1 {
		t.Fatalf("pair counter = %d, want 1", got)
	}

	conn2.SetTarget(net.TCPDestination(net.ParseAddress("198.51.100.4"), 443))
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeDestinationIP, "", "198.51.100.3", 0); got != 0 {
		t.Fatalf("updated old destination counter = %d, want 0", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeDestinationIP, "", "198.51.100.4", 0); got != 1 {
		t.Fatalf("updated new destination counter = %d, want 1", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeSourceDestinationIP, "203.0.113.10", "198.51.100.4", 0); got != 1 {
		t.Fatalf("updated pair counter = %d, want 1", got)
	}

	counters := mgr.ListConnectionCounters(CounterModeActiveConnections, CounterTypeSourceDestinationIP, 0)
	if len(counters) != 2 {
		t.Fatalf("pair counter snapshot len = %d, want 2", len(counters))
	}

	conn1.Close()
	conn2.Close()
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeSourceIP, "203.0.113.10", "", 0); got != 0 {
		t.Fatalf("source counter after close = %d, want 0", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeDestinationIP, "", "198.51.100.4", 0); got != 0 {
		t.Fatalf("destination counter after close = %d, want 0", got)
	}
}

func TestManagerCountsNewConnectionsWithinWindow(t *testing.T) {
	mgr := NewManager()
	now := time.Now()

	oldConn := mgr.NewConnection(Meta{
		Start:       now.Add(-2 * time.Minute),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.20"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
	})
	recentOne := mgr.NewConnection(Meta{
		Start:       now.Add(-20 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.20"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
	})
	recentTwo := mgr.NewConnection(Meta{
		Start:       now.Add(-10 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.20"), 12002),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.21"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.21"), 443),
	})
	defer oldConn.Close()
	defer recentOne.Close()
	defer recentTwo.Close()

	window := 30 * time.Second
	if got := mgr.CountConnections(CounterModeNewConnections, CounterTypeSourceIP, "203.0.113.20", "", window); got != 2 {
		t.Fatalf("new source counter = %d, want 2", got)
	}
	if got := mgr.CountConnections(CounterModeNewConnections, CounterTypeDestinationIP, "", "198.51.100.20", window); got != 1 {
		t.Fatalf("new destination counter = %d, want 1", got)
	}
	if got := mgr.CountConnections(CounterModeNewConnections, CounterTypeSourceDestinationIP, "203.0.113.20", "198.51.100.21", window); got != 1 {
		t.Fatalf("new pair counter = %d, want 1", got)
	}

	counters := mgr.ListConnectionCounters(CounterModeNewConnections, CounterTypeSourceIP, window)
	if len(counters) != 1 {
		t.Fatalf("new source counter snapshot len = %d, want 1", len(counters))
	}
	if counters[0].Mode != CounterModeNewConnections {
		t.Fatalf("counter mode = %v, want new", counters[0].Mode)
	}
	if counters[0].Count != 2 {
		t.Fatalf("snapshot count = %d, want 2", counters[0].Count)
	}
}

func TestManagerCountsConnectionsByPrefix(t *testing.T) {
	mgr := NewManager()

	conn1 := mgr.NewConnection(Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.2"), 443),
	})
	conn2 := mgr.NewConnection(Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.55"), 12002),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.99"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.99"), 443),
	})
	conn3 := mgr.NewConnection(Meta{
		Source:      net.TCPDestination(net.ParseAddress("203.0.114.8"), 12003),
		Destination: net.TCPDestination(net.ParseAddress("198.51.101.9"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.101.9"), 443),
	})
	defer conn1.Close()
	defer conn2.Close()
	defer conn3.Close()

	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeSourcePrefix, "203.0.113.0/24", "", 0); got != 2 {
		t.Fatalf("source prefix counter = %d, want 2", got)
	}
	if got := mgr.CountConnections(CounterModeActiveConnections, CounterTypeDestinationPrefix, "", "198.51.100.0/24", 0); got != 2 {
		t.Fatalf("destination prefix counter = %d, want 2", got)
	}
}

func TestManagerCountsNewConnectionsByPrefixWithinWindow(t *testing.T) {
	mgr := NewManager()
	now := time.Now()

	oldConn := mgr.NewConnection(Meta{
		Start:       now.Add(-2 * time.Minute),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.10"), 12000),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
	})
	recentOne := mgr.NewConnection(Meta{
		Start:       now.Add(-20 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.20"), 12001),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.20"), 443),
	})
	recentTwo := mgr.NewConnection(Meta{
		Start:       now.Add(-10 * time.Second),
		Source:      net.TCPDestination(net.ParseAddress("203.0.113.30"), 12002),
		Destination: net.TCPDestination(net.ParseAddress("198.51.100.21"), 443),
		Target:      net.TCPDestination(net.ParseAddress("198.51.100.21"), 443),
	})
	defer oldConn.Close()
	defer recentOne.Close()
	defer recentTwo.Close()

	window := 30 * time.Second
	if got := mgr.CountConnections(CounterModeNewConnections, CounterTypeSourcePrefix, "203.0.113.0/24", "", window); got != 2 {
		t.Fatalf("new source prefix counter = %d, want 2", got)
	}
	if got := mgr.CountConnections(CounterModeNewConnections, CounterTypeDestinationPrefix, "", "198.51.100.0/24", window); got != 2 {
		t.Fatalf("new destination prefix counter = %d, want 2", got)
	}
}
