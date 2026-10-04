package controller

import (
	"context"
	"fmt"

	"github.com/ImAubrey/acore/common/protocol"
	"github.com/ImAubrey/acore/core"
	"github.com/ImAubrey/acore/features/inbound"
	"github.com/ImAubrey/acore/features/outbound"
	"github.com/ImAubrey/acore/features/stats"
	"github.com/ImAubrey/acore/proxy"

	"github.com/ImAubrey/acore-backend/api"
	"github.com/ImAubrey/acore-backend/common/limiter"
)

func (c *Controller) removeInbound(tag string) error {
	return c.ibm.RemoveHandler(context.Background(), tag)
}

func (c *Controller) removeOutbound(tag string) error {
	return c.obm.RemoveHandler(context.Background(), tag)
}

func (c *Controller) addInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler")
	}
	return c.ibm.AddHandler(context.Background(), handler)
}

func (c *Controller) addOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(c.server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler")
	}
	return c.obm.AddHandler(context.Background(), handler)
}

func (c *Controller) addUsers(users []*protocol.User, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s has not implemented proxy.UserManager", tag)
	}
	for _, item := range users {
		mUser, err := item.ToMemoryUser()
		if err != nil {
			return err
		}
		err = userManager.AddUser(context.Background(), mUser)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) removeUsers(users []string, tag string) error {
	handler, err := c.ibm.GetHandler(context.Background(), tag)
	if err != nil {
		return fmt.Errorf("no such inbound tag: %s", err)
	}
	inboundInstance, ok := handler.(proxy.GetInbound)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.GetInbound", tag)
	}

	userManager, ok := inboundInstance.GetInbound().(proxy.UserManager)
	if !ok {
		return fmt.Errorf("handler %s is not implement proxy.UserManager", tag)
	}
	for _, email := range users {
		err = userManager.RemoveUser(context.Background(), email)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) getTraffic(email string) (up int64, down int64, upCounter stats.Counter, downCounter stats.Counter) {
	upName := "user>>>" + email + ">>>traffic>>>uplink"
	downName := "user>>>" + email + ">>>traffic>>>downlink"
	upCounter = c.stm.GetCounter(upName)
	downCounter = c.stm.GetCounter(downName)
	if upCounter != nil && upCounter.Value() != 0 {
		up = upCounter.Value()
	} else {
		upCounter = nil
	}
	if downCounter != nil && downCounter.Value() != 0 {
		down = downCounter.Value()
	} else {
		downCounter = nil
	}
	return up, down, upCounter, downCounter
}

func (c *Controller) resetTraffic(upCounterList *[]stats.Counter, downCounterList *[]stats.Counter) {
	for _, upCounter := range *upCounterList {
		upCounter.Set(0)
	}
	for _, downCounter := range *downCounterList {
		downCounter.Set(0)
	}
}

func (c *Controller) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalDeviceLimitConfig *limiter.GlobalDeviceLimitConfig) error {
	if c.dispatcher == nil {
		return nil
	}
	return c.dispatcher.Limiter.AddInboundLimiter(tag, nodeSpeedLimit, userList, globalDeviceLimitConfig)
}

func (c *Controller) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if c.dispatcher == nil {
		return nil
	}
	return c.dispatcher.Limiter.UpdateInboundLimiter(tag, updatedUserList)
}

func (c *Controller) DeleteInboundLimiter(tag string) error {
	if c.dispatcher == nil {
		return nil
	}
	return c.dispatcher.Limiter.DeleteInboundLimiter(tag)
}

func (c *Controller) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	if c.dispatcher == nil {
		onlineUsers := []api.OnlineUser{}
		return &onlineUsers, nil
	}
	return c.dispatcher.Limiter.GetOnlineDevice(tag)
}

func (c *Controller) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	if c.dispatcher == nil {
		return nil
	}
	return c.dispatcher.RuleManager.UpdateRule(tag, newRuleList)
}

func (c *Controller) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	if c.dispatcher == nil {
		detectResults := []api.DetectResult{}
		return &detectResults, nil
	}
	return c.dispatcher.RuleManager.GetDetectResult(tag)
}
