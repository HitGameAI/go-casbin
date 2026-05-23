/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\monitor\health_test.go
 * @Description: 测试健康检查
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package monitor

import (
	"testing"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
)

func newTestHealthChecker() *HealthChecker {
	return NewHealthChecker(logger.NewLogger())
}

func TestCheckEnforcer_Ready(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckEnforcer("ready", true)
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Equal(t, "enforcer", result.Component)
	assert.Equal(t, "enforcer is ready", result.Message)
}

func TestCheckEnforcer_Error(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckEnforcer("error", true)
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
	assert.Equal(t, "enforcer is in error state", result.Message)
}

func TestCheckEnforcer_Disabled(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckEnforcer("ready", false)
	assert.Equal(t, HealthStatusDegraded, result.Status)
	assert.Equal(t, "enforcer is disabled", result.Message)
}

func TestCheckEnforcer_UnknownState(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckEnforcer("loading", true)
	assert.Equal(t, HealthStatusDegraded, result.Status)
	assert.Contains(t, result.Message, "loading")
}

func TestCheckBreaker_Closed(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckBreaker("closed")
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Equal(t, "breaker", result.Component)
}

func TestCheckBreaker_HalfOpen(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckBreaker("half-open")
	assert.Equal(t, HealthStatusDegraded, result.Status)
}

func TestCheckBreaker_Open(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckBreaker("open")
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
}

func TestCheckBreaker_NoBreaker(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckBreaker("")
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Contains(t, result.Message, "no circuit breaker")
}

func TestCheckCache_HighHitRate(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckCache(100, 90.0)
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Equal(t, "cache", result.Component)
}

func TestCheckCache_MediumHitRate(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckCache(100, 65.0)
	assert.Equal(t, HealthStatusDegraded, result.Status)
}

func TestCheckCache_LowHitRate(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckCache(100, 30.0)
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
}

func TestHealthCheckResult_Details(t *testing.T) {
	hc := newTestHealthChecker()
	result := hc.CheckEnforcer("ready", true)
	assert.NotNil(t, result.Details)
	assert.Equal(t, "ready", result.Details["state"])
	assert.Equal(t, true, result.Details["enabled"])
	assert.False(t, result.Timestamp.IsZero())
}
