/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\monitor\monitor.go
 * @Description: 监控管理器（集成指标、健康检查、控制台输出）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"time"

	"github.com/kamalyes/go-logger"
)

type Monitor struct {
	metrics       *Metrics
	healthChecker *HealthChecker
	logger        logger.ILogger
}

func NewMonitor(log logger.ILogger) *Monitor {
	return &Monitor{
		metrics:       NewMetrics(log),
		healthChecker: NewHealthChecker(log),
		logger:        log,
	}
}

func (m *Monitor) GetMetrics() *Metrics {
	return m.metrics
}

func (m *Monitor) GetHealthChecker() *HealthChecker {
	return m.healthChecker
}

func (m *Monitor) RecordEnforce(success bool, latency time.Duration) {
	m.metrics.RecordEnforce(success, latency)
}

func (m *Monitor) RecordPolicyUpdate() {
	m.metrics.RecordPolicyUpdate()
}

func (m *Monitor) RecordCacheHit() {
	m.metrics.RecordCacheHit()
}

func (m *Monitor) RecordCacheMiss() {
	m.metrics.RecordCacheMiss()
}

func (m *Monitor) PrintReport() {
	cg := m.logger.NewConsoleGroup()

	cg.Group("Enforcer Metrics")
	snap := m.metrics.GetSnapshot()
	m.logger.InfoKV("Enforce Statistics",
		"total", snap.EnforceTotal,
		"success", snap.EnforceSuccess,
		"failure", snap.EnforceFailure,
		"success_rate", snap.SuccessRate,
		"avg_latency", snap.AvgLatency.String(),
	)
	cg.GroupEnd()

	cg.Group("Cache Statistics")
	m.logger.InfoKV("Cache Performance",
		"hits", snap.CacheHits,
		"misses", snap.CacheMisses,
		"hit_rate", snap.CacheHitRate,
	)
	cg.GroupEnd()

	cg.Group("Policy Statistics")
	m.logger.InfoKV("Policy Updates",
		"total_updates", snap.PolicyUpdates,
	)
	cg.GroupEnd()
}

func (m *Monitor) PrintHealthReport(state string, enabled bool, breakerState string, cacheSize int, cacheHitRate float64) {
	cg := m.logger.NewConsoleGroup()

	cg.Group("Health Check Results")

	enforcerHealth := m.healthChecker.CheckEnforcer(state, enabled)
	m.logger.InfoKV(enforcerHealth.Component,
		"status", string(enforcerHealth.Status),
		"message", enforcerHealth.Message,
	)

	breakerHealth := m.healthChecker.CheckBreaker(breakerState)
	m.logger.InfoKV(breakerHealth.Component,
		"status", string(breakerHealth.Status),
		"message", breakerHealth.Message,
	)

	cacheHealth := m.healthChecker.CheckCache(cacheSize, cacheHitRate)
	m.logger.InfoKV(cacheHealth.Component,
		"status", string(cacheHealth.Status),
		"message", cacheHealth.Message,
	)

	cg.GroupEnd()
}

func (m *Monitor) ResetMetrics() {
	m.metrics.Reset()
}
