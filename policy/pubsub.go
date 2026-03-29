/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\pubsub.go
 * @Description: 分布式策略变更通知 - 发布订阅接口与事件定义
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"context"
	"time"
)

// ==================== 策略变更事件 ====================

// ChangeEventType 策略变更事件类型
type ChangeEventType string

const (
	EventTypePolicyAdded   ChangeEventType = "policy_added"   // 策略添加
	EventTypePolicyRemoved ChangeEventType = "policy_removed" // 策略删除
	EventTypePolicyUpdated ChangeEventType = "policy_updated" // 策略更新
	EventTypePolicyCleared ChangeEventType = "policy_cleared" // 策略清空
	EventTypePolicyReload  ChangeEventType = "policy_reload"  // 策略全量重载
	EventTypeFullSync      ChangeEventType = "full_sync"      // 全量同步（新节点加入时）
)

// ChangeEvent 策略变更事件
// 当某个节点修改策略后，通过 Pub/Sub 广播此事件
// 其他节点收到事件后自动重载策略，实现分布式一致性
type ChangeEvent struct {
	ID        string          // 事件唯一ID（用于幂等处理）
	Type      ChangeEventType // 事件类型
	PType     string          // 策略类型（p/g）
	OldPolicy []string        // 旧策略内容（更新/删除时使用）
	NewPolicy []string        // 新策略内容（添加/更新时使用）
	Source    string          // 事件来源节点标识（节点名或 Pod 名）
	Timestamp time.Time       // 事件发生时间
}

// NewChangeEvent 创建策略变更事件
func NewChangeEvent(eventType ChangeEventType, ptype string, source string) *ChangeEvent {
	return &ChangeEvent{
		Type:      eventType,
		PType:     ptype,
		Source:    source,
		Timestamp: time.Now(),
	}
}

// ==================== 发布订阅接口 ====================

// PolicyNotifier 策略变更通知器接口
// 定义了分布式策略同步的核心发布/订阅能力
// 实现此接口的组件可以基于 Redis Pub/Sub、Kafka、NATS、RabbitMQ 等消息中间件
//
// 典型使用场景：
//   - A 节点修改策略 → 调用 Publish 广播变更事件
//   - B/C/D 节点通过 Subscribe 接收事件 → 自动 ReloadPolicy
//   - 新节点启动时通过 RequestSync 请求全量同步
type PolicyNotifier interface {
	// Publish 发布策略变更事件
	// 当本节点修改策略后调用，广播给所有订阅者
	Publish(ctx context.Context, event *ChangeEvent) error

	// Subscribe 订阅策略变更事件
	// 启动后持续监听，收到事件时调用 handler 处理
	// handler 通常执行 ReloadPolicy 或增量更新
	Subscribe(ctx context.Context, handler ChangeEventHandler) error

	// Unsubscribe 取消订阅
	// 节点关闭时调用，停止监听变更事件
	Unsubscribe() error

	// Close 关闭通知器
	// 释放所有资源（连接、goroutine 等）
	Close() error
}

// PolicySyncProvider 策略全量同步接口
// 新节点加入集群时，需要从其他节点获取完整的策略快照
// 实现此接口的组件可以基于 Redis、数据库或 HTTP 等方式获取全量策略
type PolicySyncProvider interface {
	// RequestSync 请求全量策略同步
	// 新节点启动时调用，获取最新的完整策略数据
	RequestSync(ctx context.Context) ([]string, error)

	// ProvideSync 提供全量策略数据
	// 当前节点响应其他节点的同步请求
	ProvideSync(ctx context.Context) ([]string, error)
}

// ChangeEventHandler 策略变更事件处理函数
// 收到变更事件后的回调处理逻辑
type ChangeEventHandler func(event *ChangeEvent)

// ==================== 通知器配置 ====================

// NotifierConfig 发布订阅通知器通用配置
type NotifierConfig struct {
	Channel       string        // 订阅频道名称，默认 "casbin:policy:changes"
	Source        string        // 本节点标识（用于事件溯源和避免自消费）
	BufferSize    int           // 事件缓冲区大小，默认 256
	RetryInterval time.Duration // 发布失败重试间隔，默认 1s
	RetryCount    int           // 发布失败重试次数，默认 3
}

// DefaultNotifierConfig 默认通知器配置
func DefaultNotifierConfig() *NotifierConfig {
	return &NotifierConfig{
		Channel:       "casbin:policy:changes",
		Source:        "unknown",
		BufferSize:    256,
		RetryInterval: time.Second,
		RetryCount:    3,
	}
}

// NotifierOption 通知器配置选项函数
type NotifierOption func(*NotifierConfig)

// WithChannel 设置订阅频道名称
func WithChannel(channel string) NotifierOption {
	return func(c *NotifierConfig) {
		if channel != "" {
			c.Channel = channel
		}
	}
}

// WithSource 设置本节点标识
// 用于事件溯源和避免自消费（收到自己发布的事件时跳过处理）
func WithSource(source string) NotifierOption {
	return func(c *NotifierConfig) {
		if source != "" {
			c.Source = source
		}
	}
}

// WithBufferSize 设置事件缓冲区大小
func WithBufferSize(size int) NotifierOption {
	return func(c *NotifierConfig) {
		if size > 0 {
			c.BufferSize = size
		}
	}
}

// WithRetry 设置发布失败重试参数
func WithRetry(interval time.Duration, count int) NotifierOption {
	return func(c *NotifierConfig) {
		if interval > 0 {
			c.RetryInterval = interval
		}
		if count > 0 {
			c.RetryCount = count
		}
	}
}

// ==================== 本地通知器（单机模式） ====================

// LocalNotifier 本地通知器
// 不使用任何消息中间件，仅在进程内广播事件
// 适用于单机部署或测试场景
type LocalNotifier struct {
	config   *NotifierConfig
	handlers []ChangeEventHandler
	stopCh   chan struct{}
}

// NewLocalNotifier 创建本地通知器
func NewLocalNotifier(opts ...NotifierOption) *LocalNotifier {
	config := DefaultNotifierConfig()
	for _, opt := range opts {
		opt(config)
	}

	return &LocalNotifier{
		config: config,
		stopCh: make(chan struct{}),
	}
}

// Publish 本地发布事件（直接调用所有 handler）
func (ln *LocalNotifier) Publish(ctx context.Context, event *ChangeEvent) error {
	event.Source = ln.config.Source
	for _, handler := range ln.handlers {
		handler(event)
	}
	return nil
}

// Subscribe 本地订阅（注册 handler）
func (ln *LocalNotifier) Subscribe(ctx context.Context, handler ChangeEventHandler) error {
	ln.handlers = append(ln.handlers, handler)
	return nil
}

// Unsubscribe 本地取消订阅
func (ln *LocalNotifier) Unsubscribe() error {
	ln.handlers = nil
	return nil
}

// Close 关闭本地通知器
func (ln *LocalNotifier) Close() error {
	close(ln.stopCh)
	ln.handlers = nil
	return nil
}

// ==================== 通知器辅助工具 ====================

// NotifierHelper 通知器辅助工具
// 提供通用的策略变更事件发布便捷方法，消除各通知器实现中的重复代码
// 所有通知器（Redis/Kafka/NATS）均可组合此结构体复用发布逻辑
//
// 使用方式：
//
//	type RedisNotifier struct {
//	    policy.NotifierHelper
//	    client *redis.Client
//	    // ...
//	}
//	// 只需实现 Publish(ctx, *ChangeEvent) error 即可
//	// PublishPolicyAdded/Removed/Updated/Reload 自动可用
type NotifierHelper struct {
	Publisher func(ctx context.Context, event *ChangeEvent) error // 底层发布函数
	Source    string                                              // 事件来源节点标识
}

// PublishPolicyAdded 发布策略添加事件
func (h *NotifierHelper) PublishPolicyAdded(ctx context.Context, ptype string, p []string) error {
	event := NewChangeEvent(EventTypePolicyAdded, ptype, h.Source)
	event.NewPolicy = p
	return h.Publisher(ctx, event)
}

// PublishPolicyRemoved 发布策略删除事件
func (h *NotifierHelper) PublishPolicyRemoved(ctx context.Context, ptype string, oldPolicy []string) error {
	event := NewChangeEvent(EventTypePolicyRemoved, ptype, h.Source)
	event.OldPolicy = oldPolicy
	return h.Publisher(ctx, event)
}

// PublishPolicyUpdated 发布策略更新事件
func (h *NotifierHelper) PublishPolicyUpdated(ctx context.Context, ptype string, oldPolicy, newPolicy []string) error {
	event := NewChangeEvent(EventTypePolicyUpdated, ptype, h.Source)
	event.OldPolicy = oldPolicy
	event.NewPolicy = newPolicy
	return h.Publisher(ctx, event)
}

// PublishPolicyReload 发布策略全量重载事件
func (h *NotifierHelper) PublishPolicyReload(ctx context.Context) error {
	event := NewChangeEvent(EventTypePolicyReload, "", h.Source)
	return h.Publisher(ctx, event)
}
