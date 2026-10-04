package router

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ImAubrey/acore/common/errors"
)

type weightScaler func(value, weight float64) float64

var numberFinder = regexp.MustCompile(`\d+(\.\d+)?`)

// NewWeightManager creates a new WeightManager with settings
func NewWeightManager(s []*StrategyWeight, defaultWeight float64, scaler weightScaler) *WeightManager {
	return &WeightManager{
		settings:      s,
		cache:         make(map[string]float64),
		reCache:       make(map[string]compiledWeightRegexp),
		scaler:        scaler,
		defaultWeight: defaultWeight,
	}
}

// WeightManager manages weights for specific settings
type WeightManager struct {
	settings      []*StrategyWeight
	cache         map[string]float64
	reCache       map[string]compiledWeightRegexp
	scaler        weightScaler
	defaultWeight float64
	mu            sync.RWMutex
}

type compiledWeightRegexp struct {
	re  *regexp.Regexp
	bad bool
}

// Get get the weight of specified tag
func (s *WeightManager) Get(tag string) float64 {
	s.mu.RLock()
	weight, ok := s.cache[tag]
	s.mu.RUnlock()
	if ok {
		return weight
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if weight, ok = s.cache[tag]; ok {
		return weight
	}
	weight = s.findValueLocked(tag)
	s.cache[tag] = weight
	return weight
}

// Apply applies weight to the value
func (s *WeightManager) Apply(tag string, value float64) float64 {
	return s.scaler(value, s.Get(tag))
}

func (s *WeightManager) findValueLocked(tag string) float64 {
	for _, w := range s.settings {
		matched := s.getMatchLocked(tag, w.Match, w.Regexp)
		if matched == "" {
			continue
		}
		if w.Value > 0 {
			return float64(w.Value)
		}
		// auto weight from matched
		numStr := numberFinder.FindString(matched)
		if numStr == "" {
			return s.defaultWeight
		}
		weight, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			errors.LogError(context.Background(), "unexpected error from ParseFloat: ", err)
			return s.defaultWeight
		}
		return weight
	}
	return s.defaultWeight
}

func (s *WeightManager) getMatchLocked(tag, find string, isRegexp bool) string {
	if !isRegexp {
		idx := strings.Index(tag, find)
		if idx < 0 {
			return ""
		}
		return find
	}
	if cached, ok := s.reCache[find]; ok {
		if cached.bad || cached.re == nil {
			return ""
		}
		return cached.re.FindString(tag)
	}

	r, err := regexp.Compile(find)
	if err != nil {
		errors.LogError(context.Background(), "invalid regexp: ", find, "err: ", err)
		s.reCache[find] = compiledWeightRegexp{bad: true}
		return ""
	}
	s.reCache[find] = compiledWeightRegexp{re: r}
	return r.FindString(tag)
}
