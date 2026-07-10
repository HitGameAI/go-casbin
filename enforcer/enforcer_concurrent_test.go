/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-07-10 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-07-10 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_concurrent_test.go
 * @Description: 并发事务测试，模拟分布式场景下多 goroutine 同时操作同一 enforcer
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTransactionalSyncUserRoles_Concurrent 模拟分布式场景：
// 8 个 goroutine 并发调用 TransactionalSyncUserRoles 操作同一 enforcer
// 验证：
//  1. 不出现 "transaction has already been committed or rolled back" 错误
//  2. 最终每个用户的角色状态正确
//  3. 无数据竞争导致的不一致
func TestTransactionalSyncUserRoles_Concurrent(t *testing.T) {
	e := newMemoryEnforcer(t, rbacDomainModelPath)

	// 预填充 8 个用户，每人绑定 admin 角色
	users := []string{"user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8"}
	for _, u := range users {
		err := e.AddGroupingPolicy(u, "admin", "tenant1")
		require.NoError(t, err)
	}

	// 并发：每个 goroutine 同步一个用户的角色（admin → viewer）
	var wg sync.WaitGroup
	errs := make([]error, len(users))
	for i, u := range users {
		wg.Add(1)
		uid := u
		idx := i
		go func() {
			defer wg.Done()
			rules := [][]string{{uid, "viewer", "tenant1"}}
			errs[idx] = e.TransactionalSyncUserRoles(context.Background(), uid, rules)
		}()
	}
	wg.Wait()

	// 验证无错误
	for i, err := range errs {
		assert.NoError(t, err, "user %s sync should succeed", users[i])
	}

	// 验证最终状态：每个用户应该是 viewer 而非 admin
	for _, u := range users {
		roles := e.GetRolesForUser(u, "tenant1")
		assert.Contains(t, roles, "viewer", "user %s should have viewer role", u)
		assert.NotContains(t, roles, "admin", "user %s should not have admin role", u)
	}
}

// TestTransactionalSyncUserRoles_ConcurrentSameUser 多个 goroutine 同时同步同一用户
// 验证 ExecuteInTransaction 的锁不会死锁，且最终状态一致
func TestTransactionalSyncUserRoles_ConcurrentSameUser(t *testing.T) {
	e := newMemoryEnforcer(t, rbacDomainModelPath)

	err := e.AddGroupingPolicy("alice", "admin", "tenant1")
	require.NoError(t, err)

	// 4 个 goroutine 同时同步 alice 的角色
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			rules := [][]string{{"alice", fmt.Sprintf("role%d", idx), "tenant1"}}
			errs[idx] = e.TransactionalSyncUserRoles(context.Background(), "alice", rules)
		}()
	}
	wg.Wait()

	// 至少一个应该成功
	successCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		}
	}
	assert.Greater(t, successCount, 0, "at least one sync should succeed")

	// alice 最终应该只有一个角色
	roles := e.GetRolesForUser("alice", "tenant1")
	assert.Len(t, roles, 1, "alice should have exactly one role after concurrent sync")
}

// TestEnforceCache_ConcurrentInvalidation 并发 Enforce + 策略变更
// 验证版本号缓存在并发失效时的正确性
func TestEnforceCache_ConcurrentInvalidation(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 初始 Enforce 应该通过
	ok, err := e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	require.True(t, ok)

	// 并发：读 Enforce + 写 RemovePolicy
	var wg sync.WaitGroup
	const iterations = 100

	// 读 goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = e.Enforce("alice", "data1", "read")
		}
	}()

	// 写 goroutine：删除并重新添加策略
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = e.RemovePolicy("alice", "data1", "read")
			_ = e.AddPolicy("alice", "data1", "read")
		}
	}()

	wg.Wait()

	// 最终状态应该可以 Enforce
	ok, err = e.Enforce("alice", "data1", "read")
	assert.NoError(t, err)
	assert.True(t, ok)
}

// TestEnforceCache_VersionInvalidation 验证版本号失效机制
// 策略变更后，旧缓存条目不应被命中
func TestEnforceCache_VersionInvalidation(t *testing.T) {
	e := newMemoryEnforcer(t, rbacModelPath)

	err := e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 第一次 Enforce 填充缓存
	ok, err := e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	require.True(t, ok)

	// 删除策略，缓存应失效
	err = e.RemovePolicy("alice", "data1", "read")
	require.NoError(t, err)

	// 再次 Enforce，应该返回 false（版本号不匹配，缓存失效）
	ok, err = e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	assert.False(t, ok, "cache should be invalidated after policy removal")

	// 重新添加策略，缓存应重新填充
	err = e.AddPolicy("alice", "data1", "read")
	require.NoError(t, err)

	ok, err = e.Enforce("alice", "data1", "read")
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestTransactionalDeleteUser_Concurrent 并发删除不同用户
// 验证多用户并发删除不会互相影响
func TestTransactionalDeleteUser_Concurrent(t *testing.T) {
	e := newMemoryEnforcer(t, rbacDomainModelPath)

	users := []string{"user1", "user2", "user3", "user4"}
	for _, u := range users {
		err := e.AddPolicy(u, "tenant1", "data1", "read")
		require.NoError(t, err)
		err = e.AddGroupingPolicy(u, "admin", "tenant1")
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	errs := make([]error, len(users))
	for i, u := range users {
		wg.Add(1)
		uid := u
		idx := i
		go func() {
			defer wg.Done()
			errs[idx] = e.TransactionalDeleteUser(context.Background(), uid)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "delete user %s should succeed", users[i])
	}

	// 验证所有用户都已删除
	for _, u := range users {
		roles := e.GetRolesForUser(u, "tenant1")
		assert.Empty(t, roles, "user %s should have no roles after deletion", u)
	}
}
