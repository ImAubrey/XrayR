package router

import (
	"context"

	"github.com/ImAubrey/acore/app/observatory"
	"github.com/ImAubrey/acore/common/errors"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/extension"
)

// SelectorStrategy picks the first available outbound in order.
// It falls back to later selectors when earlier ones are unhealthy.
type SelectorStrategy struct {
	ctx         context.Context
	observatory extension.Observatory
}

func (s *SelectorStrategy) InjectContext(ctx context.Context) {
	s.ctx = ctx
	_ = core.OptionalFeatures(ctx, func(observatory extension.Observatory) error {
		s.observatory = observatory
		return nil
	})
}

func (s *SelectorStrategy) GetPrincipleTarget(tags []string) []string {
	return tags
}

func (s *SelectorStrategy) OutboundStatus(tag string) (bool, bool) {
	if tag == "" {
		return false, false
	}
	if s.observatory == nil {
		return true, false
	}
	observeReport, err := s.observatory.GetObservation(s.ctx)
	if err != nil {
		errors.LogInfoInner(s.ctx, err, "selector: cannot get observation")
		return true, false
	}
	result, ok := observeReport.(*observatory.ObservationResult)
	if !ok {
		return true, false
	}
	for _, status := range result.Status {
		if status.OutboundTag == tag {
			return status.Alive, true
		}
	}
	// Untracked outbounds are treated as alive.
	return true, false
}

func (s *SelectorStrategy) PickOutbound(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	statusMap := map[string]*observatory.OutboundStatus{}
	if s.observatory != nil {
		if observeReport, err := s.observatory.GetObservation(s.ctx); err != nil {
			errors.LogInfoInner(s.ctx, err, "selector: cannot get observation")
		} else if result, ok := observeReport.(*observatory.ObservationResult); ok {
			for _, status := range result.Status {
				statusMap[status.OutboundTag] = status
			}
		}
	}
	if len(statusMap) == 0 {
		return tags[0]
	}
	for _, tag := range tags {
		if status, ok := statusMap[tag]; ok {
			if status.Alive {
				return tag
			}
			continue
		}
		// Untracked outbounds are treated as alive.
		return tag
	}
	return tags[len(tags)-1]
}
