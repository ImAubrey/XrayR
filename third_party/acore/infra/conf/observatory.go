package conf

import (
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/infra/conf/cfgcommon/duration"
)

type ObservatoryConfig struct {
	SubjectSelector   []string          `json:"subjectSelector"`
	TestURL           string            `json:"testUrl"`
	TestURLAlt        string            `json:"testURL"`
	ProbeURL          string            `json:"probeURL"`
	Interval          duration.Duration `json:"interval,omitempty"`
	ProbeInterval     duration.Duration `json:"probeInterval,omitempty"`
	Failed            int32             `json:"failed,omitempty"`
	FailedInterval    duration.Duration `json:"failed-interval,omitempty"`
	FailedIntervalAlt duration.Duration `json:"failedInterval,omitempty"`
	Tcping            bool              `json:"tcping"`
}

func (o *ObservatoryConfig) Build() (proto.Message, error) {
	testURL := firstNonEmptyString(o.TestURL, o.TestURLAlt, o.ProbeURL)
	if strings.TrimSpace(testURL) == "" {
		testURL = "https://connectivitycheck.gstatic.com/generate_204"
	}
	interval := time.Duration(o.Interval)
	if interval == 0 {
		interval = time.Duration(o.ProbeInterval)
	}
	if interval <= 0 {
		interval = 10 * time.Second
	}
	failedInterval := time.Duration(o.FailedInterval)
	if failedInterval == 0 {
		failedInterval = time.Duration(o.FailedIntervalAlt)
	}
	if failedInterval <= 0 {
		failedInterval = 2 * time.Second
	}
	failed := o.Failed
	if failed <= 0 {
		failed = 1
	}
	return &observatory.Config{
		SubjectSelector: o.SubjectSelector,
		TestUrl:         testURL,
		Interval:        int64(interval),
		Failed:          failed,
		FailedInterval:  int64(failedInterval),
		Tcping:          o.Tcping,
	}, nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
