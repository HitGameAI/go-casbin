/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\monitor\metrics_test.go
 * @Description: 测试指标收集
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

func newTestMetrics() *Metrics {
	return NewMetrics(logger.NewLogger())
}

func TestMetrics_RecordEnforce(t *testing.T) {
	m := newTestMetrics()

	m.RecordEnforce(true, 10*time.Millisecond)
	m.RecordEnforce(true, 20*time.Millisecond)
	m.RecordEnforce(false, 5*time.Millisecond)

	snap := m.GetSnapshot()
	assert.Equal(t, int64(3), snap.EnforceTotal)
	assert.Equal(t, int64(2), snap.EnforceSuccess)
	assert.Equal(t, int64(1), snap.EnforceFailure)
}

func TestMetrics_RecordPolicyUpdate(t *testing.T) {
	m := newTestMetrics()

	m.RecordPolicyUpdate()
	m.RecordPolicyUpdate()

	snap := m.GetSnapshot()
	assert.Equal(t, int64(2), snap.PolicyUpdates)
}

func TestMetrics_RecordCacheHitMiss(t *testing.T) {
	m := newTestMetrics()

	m.RecordCacheHit()
	m.RecordCacheHit()
	m.RecordCacheMiss()

	snap := m.GetSnapshot()
	assert.Equal(t, int64(2), snap.CacheHits)
	assert.Equal(t, int64(1), snap.CacheMisses)
}

func TestMetrics_SuccessRate(t *testing.T) {
	m := newTestMetrics()

	// 无数据时成功率为 0
	snap := m.GetSnapshot()
	assert.Equal(t, float64(0), snap.SuccessRate)

	m.RecordEnforce(true, time.Millisecond)
	m.RecordEnforce(true, time.Millisecond)
	m.RecordEnforce(false, time.Millisecond)

	snap = m.GetSnapshot()
	assert.InDelta(t, 66.67, snap.SuccessRate, 0.1)
}

func TestMetrics_CacheHitRate(t *testing.T) {
	m := newTestMetrics()

	// 无数据时命中率为 0
	snap := m.GetSnapshot()
	assert.Equal(t, float64(0), snap.CacheHitRate)

	m.RecordCacheHit()
	m.RecordCacheHit()
	m.RecordCacheMiss()

	snap = m.GetSnapshot()
	assert.InDelta(t, 66.67, snap.CacheHitRate, 0.1)
}

func TestMetrics_AvgLatency(t *testing.T) {
	m := newTestMetrics()

	m.RecordEnforce(true, 10*time.Millisecond)
	m.RecordEnforce(true, 30*time.Millisecond)

	snap := m.GetSnapshot()
	assert.Equal(t, 20*time.Millisecond, snap.AvgLatency)
}

func TestMetrics_Reset(t *testing.T) {
	m := newTestMetrics()

	m.RecordEnforce(true, time.Millisecond)
	m.RecordCacheHit()
	m.RecordPolicyUpdate()

	m.Reset()

	snap := m.GetSnapshot()
	assert.Equal(t, int64(0), snap.EnforceTotal)
	assert.Equal(t, int64(0), snap.EnforceSuccess)
	assert.Equal(t, int64(0), snap.EnforceFailure)
	assert.Equal(t, int64(0), snap.PolicyUpdates)
	assert.Equal(t, int64(0), snap.CacheHits)
	assert.Equal(t, int64(0), snap.CacheMisses)
	assert.Equal(t, time.Duration(0), snap.AvgLatency)
}

func TestMetrics_ConcurrentRecord(t *testing.T) {
	m := newTestMetrics()

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			m.RecordEnforce(true, time.Millisecond)
			m.RecordCacheHit()
			m.RecordPolicyUpdate()
			done <- struct{}{}
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	snap := m.GetSnapshot()
	assert.Equal(t, int64(100), snap.EnforceTotal)
	assert.Equal(t, int64(100), snap.CacheHits)
	assert.Equal(t, int64(100), snap.PolicyUpdates)
}

func TestMetrics_LogSnapshot(t *testing.T) {
	m := newTestMetrics()
	m.RecordEnforce(true, time.Millisecond)
	// 不应 panic
	m.LogSnapshot()
}
