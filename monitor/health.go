/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\monitor\health.go
 * @Description: 健康检查（执行器组件状态检测）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"time"

	"github.com/kamalyes/go-logger"
)

type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

type HealthCheckResult struct {
	Status    HealthStatus           `json:"status"`
	Component string                 `json:"component"`
	Message   string                 `json:"message,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type HealthChecker struct {
	logger logger.ILogger
}

func NewHealthChecker(log logger.ILogger) *HealthChecker {
	return &HealthChecker{logger: log}
}

func (hc *HealthChecker) CheckEnforcer(state string, enabled bool) HealthCheckResult {
	result := HealthCheckResult{
		Component: "enforcer",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	result.Details["state"] = state
	result.Details["enabled"] = enabled

	if !enabled {
		result.Status = HealthStatusDegraded
		result.Message = "enforcer is disabled"
		return result
	}

	switch state {
	case "ready":
		result.Status = HealthStatusHealthy
		result.Message = "enforcer is ready"
	case "error":
		result.Status = HealthStatusUnhealthy
		result.Message = "enforcer is in error state"
	default:
		result.Status = HealthStatusDegraded
		result.Message = "enforcer state: " + state
	}

	return result
}

func (hc *HealthChecker) CheckBreaker(breakerState string) HealthCheckResult {
	result := HealthCheckResult{
		Component: "breaker",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	result.Details["state"] = breakerState

	switch breakerState {
	case "closed":
		result.Status = HealthStatusHealthy
		result.Message = "circuit breaker is closed (normal)"
	case "half-open":
		result.Status = HealthStatusDegraded
		result.Message = "circuit breaker is half-open (recovering)"
	case "open":
		result.Status = HealthStatusUnhealthy
		result.Message = "circuit breaker is open (tripped)"
	default:
		result.Status = HealthStatusHealthy
		result.Message = "no circuit breaker configured"
	}

	return result
}

func (hc *HealthChecker) CheckCache(cacheSize int, hitRate float64) HealthCheckResult {
	result := HealthCheckResult{
		Component: "cache",
		Timestamp: time.Now(),
		Details:   make(map[string]interface{}),
	}

	result.Details["size"] = cacheSize
	result.Details["hit_rate"] = hitRate

	if hitRate >= 80 {
		result.Status = HealthStatusHealthy
		result.Message = "cache performance is good"
	} else if hitRate >= 50 {
		result.Status = HealthStatusDegraded
		result.Message = "cache hit rate is below optimal"
	} else {
		result.Status = HealthStatusUnhealthy
		result.Message = "cache hit rate is critically low"
	}

	return result
}
