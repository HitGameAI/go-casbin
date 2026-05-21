/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\flink_test.go
 * @Description: 实时风控与反黑产接口测试
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ==================== RiskEvent 测试 ====================

func TestNewRiskEvent(t *testing.T) {
	event := NewRiskEvent(RiskEventLogin, "user1", "/api/data", "read")
	assert.Equal(t, RiskEventLogin, event.Type)
	assert.Equal(t, "user1", event.Subject)
	assert.Equal(t, "/api/data", event.Object)
	assert.Equal(t, "read", event.Action)
	assert.NotZero(t, event.Timestamp)
	assert.NotNil(t, event.Context)
}

func TestRiskEvent_ChainMethods(t *testing.T) {
	event := NewRiskEvent(RiskEventAccess, "user1", "/api/data", "read").
		WithIP("192.168.1.1").
		WithDeviceID("device-001").
		WithContext("location", "Beijing")

	assert.Equal(t, "192.168.1.1", event.IP)
	assert.Equal(t, "device-001", event.DeviceID)
	assert.Equal(t, "Beijing", event.Context["location"])
}

// ==================== RiskAssessment 测试 ====================

func TestRiskAssessment_IsBlocked(t *testing.T) {
	blocked := &RiskAssessment{Action: RiskActionBlock}
	assert.True(t, blocked.IsBlocked())

	quarantined := &RiskAssessment{Action: RiskActionQuarantine}
	assert.True(t, quarantined.IsBlocked())

	allowed := &RiskAssessment{Action: RiskActionAllow}
	assert.False(t, allowed.IsBlocked())
}

func TestRiskAssessment_IsAllowed(t *testing.T) {
	allowed := &RiskAssessment{Action: RiskActionAllow}
	assert.True(t, allowed.IsAllowed())

	blocked := &RiskAssessment{Action: RiskActionBlock}
	assert.False(t, blocked.IsAllowed())
}

// ==================== RiskRule 测试 ====================

func TestNewRiskRule(t *testing.T) {
	rule := NewRiskRule("rule-001", "异常登录检测", RiskEventLogin, RiskLevelHigh)
	assert.Equal(t, "rule-001", rule.ID)
	assert.Equal(t, "异常登录检测", rule.Name)
	assert.Equal(t, RiskEventLogin, rule.Type)
	assert.Equal(t, RiskLevelHigh, rule.Level)
	assert.True(t, rule.Enabled)
	assert.NotNil(t, rule.Tags)
	assert.NotNil(t, rule.Metadata)
}

func TestRiskRule_ChainMethods(t *testing.T) {
	rule := NewRiskRule("rule-001", "异常登录", RiskEventLogin, RiskLevelHigh).
		WithCondition("count > 5").
		WithWindow(5*time.Minute, 10).
		WithAction(RiskActionBlock).
		WithScore(80.0).
		WithTags("login", "security")

	assert.Equal(t, "count > 5", rule.Condition)
	assert.Equal(t, 5*time.Minute, rule.Window)
	assert.Equal(t, 10, rule.Threshold)
	assert.Equal(t, RiskActionBlock, rule.Action)
	assert.Equal(t, 80.0, rule.Score)
	assert.Len(t, rule.Tags, 2)
}

// ==================== BlacklistEntry 测试 ====================

func TestBlacklistEntry_IsExpired(t *testing.T) {
	// 永久黑名单
	permanent := &BlacklistEntry{}
	assert.False(t, permanent.IsExpired())

	// 已过期
	expired := &BlacklistEntry{ExpireAt: time.Now().Add(-1 * time.Hour)}
	assert.True(t, expired.IsExpired())

	// 未过期
	valid := &BlacklistEntry{ExpireAt: time.Now().Add(1 * time.Hour)}
	assert.False(t, valid.IsExpired())
}

// ==================== RiskCallbackRegistry 测试 ====================

func TestRiskCallbackRegistry(t *testing.T) {
	registry := NewRiskCallbackRegistry()
	assert.NotNil(t, registry)

	called := false
	registry.Register(RiskLevelHigh, func(assessment *RiskAssessment, event *RiskEvent) {
		called = true
	})

	assessment := &RiskAssessment{Level: RiskLevelHigh}
	event := NewRiskEvent(RiskEventLogin, "user1", "/api", "read")
	registry.Trigger(assessment, event)
	assert.True(t, called)

	// 未注册的级别不触发
	called = false
	lowAssessment := &RiskAssessment{Level: RiskLevelLow}
	registry.Trigger(lowAssessment, event)
	assert.False(t, called)
}
