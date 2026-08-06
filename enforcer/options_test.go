/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\options_test.go
 * @Description: 测试执行器配置选项
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */
package enforcer

import (
	"testing"
	"time"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/retry"
	"github.com/stretchr/testify/assert"
)

func TestDefaultOptions(t *testing.T) {
	o := defaultOptions()
	assert.True(t, o.autoSave, "autoSave should default to true")
	assert.True(t, o.enabled, "enabled should default to true")
	assert.False(t, o.watcher, "watcher should default to false")
	assert.Equal(t, 5*time.Second, o.watchInterval, "watchInterval should default to 5s")
}

func TestWithModelPath(t *testing.T) {
	o := defaultOptions()
	WithModelPath("/path/to/model.conf")(o)
	assert.Equal(t, "/path/to/model.conf", o.modelPath)
}

func TestWithPolicyPath(t *testing.T) {
	o := defaultOptions()
	WithPolicyPath("/path/to/policy.csv")(o)
	assert.Equal(t, "/path/to/policy.csv", o.policyPath)
}

func TestWithModelText(t *testing.T) {
	o := defaultOptions()
	text := `[request_definition]
r = sub, obj, act`
	WithModelText(text)(o)
	assert.Equal(t, text, o.modelText)
}

func TestWithLogger(t *testing.T) {
	o := defaultOptions()
	log := logger.NewLogger()
	WithLogger(log)(o)
	assert.Equal(t, log, o.logger)
}

func TestWithBreaker(t *testing.T) {
	o := defaultOptions()
	WithBreaker("test-breaker", breaker.Config{MaxFailures: 5})(o)
	assert.NotNil(t, o.breaker)
}

func TestWithRetry(t *testing.T) {
	o := defaultOptions()
	r := retry.NewRetry()
	WithRetry(r)(o)
	assert.NotNil(t, o.retry)
}

func TestWithAutoSave(t *testing.T) {
	o := defaultOptions()
	WithAutoSave(false)(o)
	assert.False(t, o.autoSave)
}

func TestWithEnabled(t *testing.T) {
	o := defaultOptions()
	WithEnabled(false)(o)
	assert.False(t, o.enabled)
}

func TestWithWatcher(t *testing.T) {
	o := defaultOptions()
	WithWatcher(true)(o)
	assert.True(t, o.watcher)
	assert.Equal(t, 5*time.Second, o.watchInterval)

	WithWatcher(true, 10*time.Second)(o)
	assert.Equal(t, 10*time.Second, o.watchInterval)
}

func TestWithNotifier(t *testing.T) {
	o := defaultOptions()
	// 使用 nil 测试，因为 PolicyNotifier 是接口
	WithNotifier(nil)(o)
	assert.Nil(t, o.notifier)
}

func TestWithAdapter(t *testing.T) {
	o := defaultOptions()
	adapter := policy.NewMemoryAdapter()
	WithAdapter(adapter)(o)
	assert.Equal(t, adapter, o.adapter)
}

func TestWithPublicPolicies(t *testing.T) {
	o := defaultOptions()
	WithPublicPolicies([][]string{
		{"/v1/login", "POST"},
		{"/v1/refresh", "POST"},
	})(o)
	expected := [][]string{
		{SubjectAnonymous, "/v1/login", "POST"},
		{SubjectAnonymous, "/v1/refresh", "POST"},
	}
	assert.Equal(t, expected, o.publicPolicies)
}

func TestWithAuthSkipPolicies(t *testing.T) {
	o := defaultOptions()
	WithAuthSkipPolicies([][]string{
		{"/v1/auth/user-info", "GET"},
	})(o)
	expected := [][]string{
		{SubjectAuthenticated, "/v1/auth/user-info", "GET"},
	}
	assert.Equal(t, expected, o.authSkipPolicies)
}

func TestOptionsChaining(t *testing.T) {
	o := defaultOptions()
	WithModelPath("/model.conf")(o)
	WithAutoSave(false)(o)
	WithEnabled(true)(o)
	WithPublicPolicies([][]string{{"/health", "GET"}})(o)
	WithAuthSkipPolicies([][]string{{"/me", "GET"}})(o)

	assert.Equal(t, "/model.conf", o.modelPath)
	assert.False(t, o.autoSave)
	assert.True(t, o.enabled)
	assert.Len(t, o.publicPolicies, 1)
	assert.Equal(t, SubjectAnonymous, o.publicPolicies[0][0])
	assert.Len(t, o.authSkipPolicies, 1)
	assert.Equal(t, SubjectAuthenticated, o.authSkipPolicies[0][0])
}

func TestWithNormalizeHost(t *testing.T) {
	o := defaultOptions()
	fn := func(host string) string { return "normalized-" + host }
	WithNormalizeHost(fn)(o)
	assert.NotNil(t, o.normalizeHost)
	assert.Equal(t, "normalized-example.com", o.normalizeHost("example.com"))
}

func TestWithNormalizeHost_Nil(t *testing.T) {
	o := defaultOptions()
	WithNormalizeHost(nil)(o)
	assert.Nil(t, o.normalizeHost)
}
