/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\options.go
 * @Description: 执行器配置选项（链式 API）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"time"

	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/retry"
)

// Options 执行器配置项
// 所有字段均为私有，通过 WithXxx 选项函数设置，支持链式调用
type Options struct {
	modelPath        string                // 模型文件路径（如 resources/rbac_model.conf）
	policyPath       string                // 策略文件路径（如 resources/rbac_policy.csv）
	modelText        string                // 模型文本内容（与 modelPath 二选一）
	logger           logger.ILogger        // 日志记录器（基于 go-logger）
	breaker          *breaker.Circuit      // 熔断器（基于 go-toolbox/breaker，保护下游存储）
	retry            *retry.Retry          // 重试器（基于 go-toolbox/retry，自动重试失败操作）
	adapter          policy.Adapter        // 外部策略适配器（ORM/Redis 等，优先于文件适配器）
	notifier         policy.PolicyNotifier // 分布式策略变更通知器（Redis Pub/Sub/Kafka/NATS）
	autoSave         bool                  // 是否自动保存策略变更到适配器
	enabled          bool                  // 执行器是否启用（禁用时所有 Enforce 返回错误）
	watcher          bool                  // 是否启用文件变更监控（单机热更新）
	watchInterval    time.Duration         // 文件变更监控间隔
	publicPolicies   [][]string            // 公开接口策略（允许匿名访问的路径，不持久化到适配器）
	authSkipPolicies [][]string            // 认证免鉴权策略（需 JWT 但跳过 Casbin 的路径，不持久化到适配器）
}

// defaultOptions 返回默认配置
// autoSave 默认开启，enabled 默认开启，watcher 默认关闭
func defaultOptions() *Options {
	return &Options{
		autoSave:      true,
		enabled:       true,
		watcher:       false,
		watchInterval: 5 * time.Second,
	}
}

// Option 配置选项函数类型
type Option func(*Options)

// WithModelPath 设置模型文件路径
// 路径可自定义，不限于 resources 目录
// 与 WithModelText 二选一，modelPath 优先
func WithModelPath(path string) Option {
	return func(o *Options) {
		o.modelPath = path
	}
}

// WithPolicyPath 设置策略文件路径
// 仅在使用文件适配器时需要设置
// 如果使用了 WithAdapter，则不需要设置此选项
func WithPolicyPath(path string) Option {
	return func(o *Options) {
		o.policyPath = path
	}
}

// WithModelText 设置模型文本内容
// 适用于模型配置动态生成的场景
// 与 WithModelPath 二选一，modelPath 优先
func WithModelText(text string) Option {
	return func(o *Options) {
		o.modelText = text
	}
}

// WithLogger 设置日志记录器
// 基于 go-logger，支持结构化日志、分布式追踪、Console 风格
func WithLogger(log logger.ILogger) Option {
	return func(o *Options) {
		o.logger = log
	}
}

// WithBreaker 设置熔断器
// 基于 go-toolbox/breaker，当下游存储（MySQL/Redis）故障时自动熔断
// 防止级联故障，保护系统稳定性
// name: 熔断器名称（用于日志标识）
// config: 熔断器配置（MaxFailures 最大失败次数、ResetTimeout 熔断恢复时间）
func WithBreaker(name string, config breaker.Config) Option {
	return func(o *Options) {
		o.breaker = breaker.New(name, config)
	}
}

// WithRetry 设置重试器
// 基于 go-toolbox/retry，支持指数退避和抖动
// 适用于网络抖动等临时性故障的自动重试
func WithRetry(r *retry.Retry) Option {
	return func(o *Options) {
		o.retry = r
	}
}

// WithAutoSave 设置是否自动保存策略变更到适配器
// 开启后 AddPolicy/RemovePolicy 等操作会自动持久化
// 关闭后需要手动调用 SavePolicy 保存
func WithAutoSave(autoSave bool) Option {
	return func(o *Options) {
		o.autoSave = autoSave
	}
}

// WithEnabled 设置执行器是否启用
// 禁用时所有 Enforce 调用返回 EnforcerDisabledError
// 适用于系统维护期间临时关闭权限校验
func WithEnabled(enabled bool) Option {
	return func(o *Options) {
		o.enabled = enabled
	}
}

// WithWatcher 设置文件变更监控
// 开启后自动监控策略文件变更并热更新
// 适用于单机部署场景，分布式场景请使用 WithNotifier
// enabled: 是否启用
// interval: 可选，监控间隔，默认 5 秒
func WithWatcher(enabled bool, interval ...time.Duration) Option {
	return func(o *Options) {
		o.watcher = enabled
		if len(interval) > 0 {
			o.watchInterval = interval[0]
		}
	}
}

// WithNotifier 设置分布式策略变更通知器
// 通知器用于在分布式环境下广播策略变更，实现多节点自动同步
// 支持 Redis Pub/Sub、Kafka、NATS 等实现
// A 节点修改策略后，通过通知器广播，B/C/D 节点收到后自动重载
func WithNotifier(notifier policy.PolicyNotifier) Option {
	return func(o *Options) {
		o.notifier = notifier
	}
}

// WithAdapter 设置外部策略适配器
// 适配器用于策略的持久化存储，支持 ORM（MySQL/PostgreSQL/SQLite）、Redis 等
// 设置后优先使用外部适配器，不再使用文件适配器
// 多租户场景下，每个租户使用独立的适配器实例（独立表/独立前缀）
func WithAdapter(adapter policy.Adapter) Option {
	return func(o *Options) {
		o.adapter = adapter
	}
}

// WithPublicPolicies 设置公开接口策略
// 公开策略定义允许匿名用户访问的路径和方法
// 这些策略仅在内存中维护，不会持久化到适配器
// 每次服务启动时从代码重新加载，确保修改即时生效
//
// 策略格式：只需传入路径和方法（不含主体），系统自动补充 SubjectAnonymous 前缀
//   - RBAC: {"/v1/login", "POST"}
//   - RBAC Domain: {"public", "/v1/login", "POST"}
//
// 使用示例：
//
//	e, _ := enforcer.NewEnforcer(
//	    enforcer.WithModelText(rbacModel),
//	    enforcer.WithPublicPolicies([][]string{
//	        {"/v1/login", "POST"},
//	        {"/v1/refresh", "POST"},
//	    }),
//	)
//	ok, _ := e.IsPublicPolicy("/v1/login", "POST") // true
func WithPublicPolicies(policies [][]string) Option {
	return func(o *Options) {
		o.publicPolicies = prependSubject(SubjectAnonymous, policies)
	}
}

// WithAuthSkipPolicies 设置认证免鉴权策略
// 认证免鉴权策略定义需要 JWT 验证但跳过 Casbin 权限校验的路径和方法
// 这些策略仅在内存中维护，不会持久化到适配器
// 每次服务启动时从代码重新加载，确保修改即时生效
//
// 策略格式：只需传入路径和方法（不含主体），系统自动补充 SubjectAuthenticated 前缀
//   - RBAC: {"/v1/auth/user-info", "GET"}
//   - RBAC Domain: {"tenant::x", "/v1/auth/user-info", "GET"}
//
// 使用示例：
//
//	e, _ := enforcer.NewEnforcer(
//	    enforcer.WithModelText(rbacModel),
//	    enforcer.WithAuthSkipPolicies([][]string{
//	        {"/v1/auth/user-info", "GET"},
//	    }),
//	)
//	ok, _ := e.IsAuthSkipPolicy("/v1/auth/user-info", "GET") // true
func WithAuthSkipPolicies(policies [][]string) Option {
	return func(o *Options) {
		o.authSkipPolicies = prependSubject(SubjectAuthenticated, policies)
	}
}

// prependSubject 为每条策略自动在头部插入主体标识
// 避免调用方手动填写 SubjectAnonymous/SubjectAuthenticated，减少出错可能
func prependSubject(subject string, policies [][]string) [][]string {
	result := make([][]string, len(policies))
	for i, p := range policies {
		result[i] = append([]string{subject}, p...)
	}
	return result
}
