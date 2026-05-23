/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\monitor\monitor_test.go
 * @Description: 测试监控管理器
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package monitor

import (
	"testing"
	"time"

	"github.com/kamalyes/go-logger"
	"github.com/stretchr/testify/assert"
)

func newTestMonitor() *Monitor {
	return NewMonitor(logger.NewLogger())
}

func TestMonitor_GetMetrics(t *testing.T) {
	m := newTestMonitor()
	assert.NotNil(t, m.GetMetrics())
}

func TestMonitor_GetHealthChecker(t *testing.T) {
	m := newTestMonitor()
	assert.NotNil(t, m.GetHealthChecker())
}

func TestMonitor_RecordEnforce(t *testing.T) {
	m := newTestMonitor()
	m.RecordEnforce(true, 10*time.Millisecond)
	m.RecordEnforce(false, 5*time.Millisecond)

	snap := m.GetMetrics().GetSnapshot()
	assert.Equal(t, int64(2), snap.EnforceTotal)
	assert.Equal(t, int64(1), snap.EnforceSuccess)
	assert.Equal(t, int64(1), snap.EnforceFailure)
}

func TestMonitor_RecordPolicyUpdate(t *testing.T) {
	m := newTestMonitor()
	m.RecordPolicyUpdate()

	snap := m.GetMetrics().GetSnapshot()
	assert.Equal(t, int64(1), snap.PolicyUpdates)
}

func TestMonitor_RecordCacheHitMiss(t *testing.T) {
	m := newTestMonitor()
	m.RecordCacheHit()
	m.RecordCacheMiss()

	snap := m.GetMetrics().GetSnapshot()
	assert.Equal(t, int64(1), snap.CacheHits)
	assert.Equal(t, int64(1), snap.CacheMisses)
}

func TestMonitor_ResetMetrics(t *testing.T) {
	m := newTestMonitor()
	m.RecordEnforce(true, time.Millisecond)
	m.RecordCacheHit()

	m.ResetMetrics()

	snap := m.GetMetrics().GetSnapshot()
	assert.Equal(t, int64(0), snap.EnforceTotal)
	assert.Equal(t, int64(0), snap.CacheHits)
}

func TestMonitor_PrintReport(t *testing.T) {
	m := newTestMonitor()
	m.RecordEnforce(true, time.Millisecond)
	// 不应 panic
	m.PrintReport()
}

func TestMonitor_PrintHealthReport(t *testing.T) {
	m := newTestMonitor()
	// 不应 panic
	m.PrintHealthReport("ready", true, "closed", 100, 85.0)
}
