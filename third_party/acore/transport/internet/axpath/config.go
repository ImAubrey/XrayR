package axpath

import (
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}

func (c *Config) GetNormalizedSubflows() int {
	n := int(c.GetSubflows())
	if n <= 0 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	// Keep a small, sane upper bound by default. This is a transport-level
	// feature and each subflow consumes a full TCP socket.
	if n > 16 {
		n = 16
	}
	return n
}

func (c *Config) GetNormalizedChunkSize() int {
	n := int(c.GetChunkSize())
	if n <= 0 {
		n = 32768
	}
	if n < 1024 {
		n = 1024
	}
	if n > 1024*1024 {
		n = 1024 * 1024
	}
	return n
}

func (c *Config) GetNormalizedAckMaskBits() int {
	n := int(c.GetAckMaskBits())
	if n <= 0 {
		// Larger default improves loss recovery on high-BDP / reordering paths.
		n = 1024
	}
	if n < 8 {
		n = 8
	}
	if n > 4096 {
		n = 4096
	}
	// Force multiple-of-8.
	n = (n / 8) * 8
	if n < 8 {
		n = 8
	}
	return n
}

func (c *Config) GetNormalizedMaxInflightBytes() int {
	n := int(c.GetMaxInflightBytes())
	if n <= 0 {
		// Increase default to reduce "stuck at 16MiB" stalls on lossy/reordering paths.
		n = 32 * 1024 * 1024
	}
	if n < 1024*1024 {
		n = 1024 * 1024
	}
	if n > 512*1024*1024 {
		n = 512 * 1024 * 1024
	}
	return n
}

func (c *Config) GetNormalizedMaxQueuePerFlow() int {
	n := int(c.GetMaxQueuePerFlow())
	if n <= 0 {
		// Allow a bit more buffering per subflow so control frames (ACK) are less
		// likely to be delayed behind data on full-duplex workloads (e.g. mux).
		n = 32
	}
	if n < 1 {
		n = 1
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

func (c *Config) GetNormalizedJoinTimeout() time.Duration {
	ms := int(c.GetJoinTimeoutMs())
	if ms <= 0 {
		ms = 16000
	}
	if ms < 500 {
		ms = 500
	}
	if ms > 10*60*1000 {
		ms = 10 * 60 * 1000
	}
	return time.Duration(ms) * time.Millisecond
}

func (c *Config) GetNormalizedResumeTimeout() time.Duration {
	ms := int(c.GetResumeTimeoutMs())
	if ms <= 0 {
		ms = 10000
	}
	if ms < 0 {
		ms = 0
	}
	if ms > 10*60*1000 {
		ms = 10 * 60 * 1000
	}
	return time.Duration(ms) * time.Millisecond
}

func (c *Config) GetNormalizedReconnect() bool {
	if c == nil || c.Reconnect == nil {
		return true
	}
	return *c.Reconnect
}

func (c *Config) GetNormalizedPsk() string {
	if c == nil {
		return ""
	}
	return c.GetPsk()
}
