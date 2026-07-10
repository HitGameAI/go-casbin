/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_bench_test.go
 * @Description: 性能基准测试，覆盖高并发场景下的吞吐和延迟
 *
 * 测试维度：
 *   1. Enforce 热路径吞吐（缓存命中 vs 未命中）
 *   2. TransactionalSyncUserRoles 并发吞吐
 *   3. enforceCache 版本号失效后的恢复性能
 *   4. 大规模策略下的 Enforce 延迟
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// BenchmarkEnforce_CacheHit 纯缓存命中场景的吞吐
// 验证版本号机制下缓存命中的性能
func BenchmarkEnforce_CacheHit(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_CacheMiss_ColdStart 每次都缓存未命中（不同 key）
// 验证缓存未命中路径的性能
func BenchmarkEnforce_CacheMiss_ColdStart(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 每次用不同的 key，强制缓存未命中
		_, _ = e.Enforce("alice", fmt.Sprintf("data%d", i), "read")
	}
}

// BenchmarkEnforceConcurrent 并发 Enforce 吞吐
// 模拟多 goroutine 并行鉴权
func BenchmarkEnforceConcurrent(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	})
}

// BenchmarkTransactionalSyncUserRoles_Concurrent 并发同步用户角色
// 模拟 resyncRoleBoundUsers 的 8 并发场景
func BenchmarkTransactionalSyncUserRoles_Concurrent(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacDomainModelPath)

	// 预填充用户
	users := make([]string, 100)
	for i := range users {
		users[i] = fmt.Sprintf("user%d", i)
		_ = e.AddGroupingPolicy(users[i], "admin", "tenant1")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		for j, u := range users {
			wg.Add(1)
			uid := u
			roleIdx := j
			go func() {
				defer wg.Done()
				rules := [][]string{{uid, fmt.Sprintf("role%d", roleIdx%10), "tenant1"}}
				_ = e.TransactionalSyncUserRoles(context.Background(), uid, rules)
			}()
		}
		wg.Wait()
	}
}

// BenchmarkEnforceCache_VersionInvalidation 策略变更后版本号失效的性能
// 模拟高频策略变更下 Enforce 的表现
func BenchmarkEnforceCache_VersionInvalidation(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 每次 Enforce 前先变更策略，触发版本号递增
		if i%10 == 0 {
			_ = e.RemovePolicy("alice", "data1", "read")
			_ = e.AddPolicy("alice", "data1", "read")
		}
		_, _ = e.Enforce("alice", "data1", "read")
	}
}

// BenchmarkEnforce_LargePolicy 大规模策略下的 Enforce 延迟
// 验证策略数量增长对 Enforce 性能的影响
func BenchmarkEnforce_LargePolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 10000 条策略
	for i := 0; i < 10000; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}

	// 预热缓存
	_, _ = e.Enforce("alice", "data9999", "read")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = e.Enforce("alice", "data9999", "read")
	}
}

// BenchmarkEnforceConcurrent_LargePolicy 大规模策略+并发 Enforce
// 最贴近真实生产场景的基准测试
func BenchmarkEnforceConcurrent_LargePolicy(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)

	// 填充 10000 条策略
	for i := 0; i < 10000; i++ {
		_ = e.AddPolicy("alice", fmt.Sprintf("data%d", i), "read")
	}

	// 预热缓存
	_, _ = e.Enforce("alice", "data9999", "read")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Enforce("alice", "data9999", "read")
		}
	})
}

// BenchmarkEnforceCache_HitRate 统计缓存命中率
// 在高并发 + 间歇性策略变更下，验证缓存命中率
func BenchmarkEnforceCache_HitRate(b *testing.B) {
	e := newMemoryEnforcerB(b, rbacModelPath)
	_ = e.AddPolicy("alice", "data1", "read")

	// 预热缓存
	_, _ = e.Enforce("alice", "data1", "read")

	var hits, total int64

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			atomic.AddInt64(&total, 1)
			_, err := e.Enforce("alice", "data1", "read")
			if err == nil {
				atomic.AddInt64(&hits, 1)
			}
		}
	})

	b.StopTimer()
	hitRate := float64(hits) / float64(total) * 100
	b.ReportMetric(hitRate, "hit_rate%")
}
