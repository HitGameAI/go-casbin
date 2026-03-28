/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\monitor\metrics.go
 * @Description: 指标收集（基于原子计数器）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package monitor

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/moment"
)

type Metrics struct {
	enforceTotal   atomic.Int64
	enforceSuccess atomic.Int64
	enforceFailure atomic.Int64
	policyUpdates  atomic.Int64
	cacheHits      atomic.Int64
	cacheMisses    atomic.Int64
	totalLatencyNs atomic.Int64
	logger         logger.ILogger
}

func NewMetrics(log logger.ILogger) *Metrics {
	return &Metrics{logger: log}
}

func (m *Metrics) RecordEnforce(success bool, latency time.Duration) {
	m.enforceTotal.Add(1)
	if success {
		m.enforceSuccess.Add(1)
	} else {
		m.enforceFailure.Add(1)
	}
	m.totalLatencyNs.Add(latency.Nanoseconds())
}

func (m *Metrics) RecordPolicyUpdate() {
	m.policyUpdates.Add(1)
}

func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Add(1)
}

func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Add(1)
}

func (m *Metrics) GetSnapshot() MetricsSnapshot {
	total := m.enforceTotal.Load()
	var avgLatency time.Duration
	if total > 0 {
		avgLatency = time.Duration(m.totalLatencyNs.Load() / total)
	}

	return MetricsSnapshot{
		EnforceTotal:   total,
		EnforceSuccess: m.enforceSuccess.Load(),
		EnforceFailure: m.enforceFailure.Load(),
		PolicyUpdates:  m.policyUpdates.Load(),
		CacheHits:      m.cacheHits.Load(),
		CacheMisses:    m.cacheMisses.Load(),
		AvgLatency:     avgLatency,
		SuccessRate:    m.calculateSuccessRate(total),
		CacheHitRate:   m.calculateCacheHitRate(),
		CollectedAt:    moment.NowTime(nil),
	}
}

func (m *Metrics) calculateSuccessRate(total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(m.enforceSuccess.Load()) / float64(total) * 100
}

func (m *Metrics) calculateCacheHitRate() float64 {
	hits := m.cacheHits.Load()
	total := hits + m.cacheMisses.Load()
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

func (m *Metrics) Reset() {
	m.enforceTotal.Store(0)
	m.enforceSuccess.Store(0)
	m.enforceFailure.Store(0)
	m.policyUpdates.Store(0)
	m.cacheHits.Store(0)
	m.cacheMisses.Store(0)
	m.totalLatencyNs.Store(0)
	m.logger.InfoMsg("Metrics reset")
}

func (m *Metrics) LogSnapshot() {
	snap := m.GetSnapshot()
	m.logger.InfoKV("Metrics snapshot",
		"enforce_total", snap.EnforceTotal,
		"enforce_success", snap.EnforceSuccess,
		"enforce_failure", snap.EnforceFailure,
		"success_rate", fmt.Sprintf("%.2f%%", snap.SuccessRate),
		"policy_updates", snap.PolicyUpdates,
		"cache_hits", snap.CacheHits,
		"cache_misses", snap.CacheMisses,
		"avg_latency", snap.AvgLatency.String(),
	)
}

type MetricsSnapshot struct {
	EnforceTotal   int64
	EnforceSuccess int64
	EnforceFailure int64
	PolicyUpdates  int64
	CacheHits      int64
	CacheMisses    int64
	AvgLatency     time.Duration
	SuccessRate    float64
	CacheHitRate   float64
	CollectedAt    time.Time
}
