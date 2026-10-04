package router

import "github.com/ImAubrey/acore/features/routing"

// RuleTagCondition checks presence/absence of prior matched rule tags.
type RuleTagCondition struct {
	require []string
	exclude []string
}

func NewRuleTagCondition(tags []string) (*RuleTagCondition, error) {
	rtc := &RuleTagCondition{}
	for _, t := range tags {
		if t == "" {
			continue
		}
		if t[0] == '!' {
			if len(t) > 1 {
				rtc.exclude = append(rtc.exclude, t[1:])
			}
			continue
		}
		rtc.require = append(rtc.require, t)
	}
	return rtc, nil
}

func (c *RuleTagCondition) Apply(ctx routing.Context) bool {
	tmgr, ok := ctx.(routing.RuleTagManager)
	if !ok {
		// cannot satisfy any require check
		return len(c.require) == 0 && len(c.exclude) == 0
	}
	requireHit := len(c.require) == 0
	for _, t := range c.require {
		if tmgr.HasRuleTag(t) {
			requireHit = true
			break
		}
	}
	if !requireHit {
		return false
	}
	for _, t := range c.exclude {
		if tmgr.HasRuleTag(t) {
			return false
		}
	}
	return true
}
