package router

import (
	"strings"

	"github.com/ImAubrey/acore/common/errors"
)

func detectBalancerLoop(balancers map[string]*Balancer) error {
	if len(balancers) == 0 {
		return nil
	}
	const (
		stateUnvisited = iota
		stateVisiting
		stateDone
	)
	states := make(map[string]int, len(balancers))
	var visit func(tag string, path []string) error
	visit = func(tag string, path []string) error {
		switch states[tag] {
		case stateVisiting:
			cycle := append(path, tag)
			return errors.New("balancer loop detected: ", strings.Join(cycle, " -> "))
		case stateDone:
			return nil
		}
		states[tag] = stateVisiting
		balancer := balancers[tag]
		for _, dep := range balancerDependencies(balancer, balancers) {
			if err := visit(dep, append(path, tag)); err != nil {
				return err
			}
		}
		states[tag] = stateDone
		return nil
	}
	for tag := range balancers {
		if states[tag] != stateUnvisited {
			continue
		}
		if err := visit(tag, nil); err != nil {
			return err
		}
	}
	return nil
}

func balancerDependencies(balancer *Balancer, balancers map[string]*Balancer) []string {
	if balancer == nil || len(balancers) == 0 {
		return nil
	}
	deps := make([]string, 0)
	seen := make(map[string]struct{})
	add := func(tag string) {
		if tag == "" {
			return
		}
		if _, ok := balancers[tag]; !ok {
			return
		}
		if _, ok := seen[tag]; ok {
			return
		}
		seen[tag] = struct{}{}
		deps = append(deps, tag)
	}
	for _, selector := range balancer.selectors {
		add(selector)
	}
	add(balancer.fallbackTag)
	return deps
}
