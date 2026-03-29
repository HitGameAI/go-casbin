/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\flink.go
 * @Description: 实时风控与反黑产接口 - 基于 Flink 的流式规则引擎集成
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"context"
	"time"
)

// ==================== 风控事件 ====================

// RiskLevel 风险等级
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"       // 低风险：正常访问
	RiskLevelMedium   RiskLevel = "medium"    // 中风险：需要二次验证
	RiskLevelHigh     RiskLevel = "high"      // 高风险：需要人工审核
	RiskLevelCritical RiskLevel = "critical"  // 极高风险：立即拦截
)

// RiskEventType 风控事件类型
type RiskEventType string

const (
	RiskEventLogin       RiskEventType = "login"        // 登录事件
	RiskEventAccess      RiskEventType = "access"       // 访问事件
	RiskEventTransaction RiskEventType = "transaction"  // 交易事件
	RiskEventAPI         RiskEventType = "api"          // API 调用事件
	RiskEventBatch       RiskEventType = "batch"        // 批量操作事件
)

// RiskEvent 风控事件
// 描述一次需要风控评估的事件，包含主体、资源、操作及上下文信息
type RiskEvent struct {
	ID        string                 // 事件唯一 ID
	Type      RiskEventType          // 事件类型
	Subject   string                 // 主体（用户 ID / IP / 设备 ID）
	Object    string                 // 客体（资源 / API / 交易对象）
	Action    string                 // 操作（read/write/transfer 等）
	IP        string                 // 来源 IP
	DeviceID  string                 // 设备 ID
	Timestamp time.Time              // 事件时间
	Context   map[string]interface{} // 扩展上下文（地理位置、UA 等）
}

// NewRiskEvent 创建风控事件
func NewRiskEvent(eventType RiskEventType, subject, object, action string) *RiskEvent {
	return &RiskEvent{
		Type:      eventType,
		Subject:   subject,
		Object:    object,
		Action:    action,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}
}

// WithIP 设置来源 IP
func (re *RiskEvent) WithIP(ip string) *RiskEvent {
	re.IP = ip
	return re
}

// WithDeviceID 设置设备 ID
func (re *RiskEvent) WithDeviceID(deviceID string) *RiskEvent {
	re.DeviceID = deviceID
	return re
}

// WithContext 添加扩展上下文
func (re *RiskEvent) WithContext(key string, value interface{}) *RiskEvent {
	re.Context[key] = value
	return re
}

// ==================== 风控评估结果 ====================

// RiskAssessment 风控评估结果
type RiskAssessment struct {
	EventID    string            // 关联的事件 ID
	Level      RiskLevel         // 风险等级
	Score      float64           // 风险分数（0-100，越高越危险）
	Reason     string            // 风险原因描述
	Rules      []string          // 触发的规则列表
	Action     RiskAction        // 建议动作
	ExpireAt   time.Time         // 评估结果过期时间
	Metadata   map[string]string // 扩展元数据
}

// RiskAction 风控建议动作
type RiskAction string

const (
	RiskActionAllow    RiskAction = "allow"     // 允许通过
	RiskActionVerify   RiskAction = "verify"    // 需要二次验证（短信/邮箱/人脸）
	RiskActionChallenge RiskAction = "challenge" // 人机验证（验证码）
	RiskActionReview   RiskAction = "review"    // 人工审核
	RiskActionBlock    RiskAction = "block"     // 直接拦截
	RiskActionQuarantine RiskAction = "quarantine" // 隔离观察
)

// IsBlocked 判断是否应被拦截
func (ra *RiskAssessment) IsBlocked() bool {
	return ra.Action == RiskActionBlock || ra.Action == RiskActionQuarantine
}

// IsAllowed 判断是否允许通过
func (ra *RiskAssessment) IsAllowed() bool {
	return ra.Action == RiskActionAllow
}

// ==================== Flink 流式规则引擎接口 ====================

// FlinkRuleEngine Flink 流式规则引擎接口
// 对接 Apache Flink 实现实时风控规则计算
// 典型场景：
//   - 实时检测异常登录（异地登录、频繁失败）
//   - 交易反欺诈（异常金额、高频交易）
//   - API 滥用检测（爬虫、暴力破解）
//   - 批量操作检测（黑产批量注册、刷单）
type FlinkRuleEngine interface {
	// Evaluate 实时评估风控事件
	// 将事件发送到 Flink 流处理引擎，返回风控评估结果
	// 支持同步和异步模式：
	//   - 同步模式：等待 Flink 计算完成后返回结果
	//   - 异步模式：立即返回，结果通过回调通知
	Evaluate(ctx context.Context, event *RiskEvent) (*RiskAssessment, error)

	// EvaluateBatch 批量评估风控事件
	// 用于批量操作场景，一次性评估多个事件
	EvaluateBatch(ctx context.Context, events []*RiskEvent) ([]*RiskAssessment, error)

	// SubmitRule 提交风控规则到 Flink
	// 动态添加风控规则，Flink 会实时加载并应用
	SubmitRule(ctx context.Context, rule *RiskRule) error

	// RemoveRule 从 Flink 移除风控规则
	RemoveRule(ctx context.Context, ruleID string) error

	// GetRule 获取指定风控规则
	GetRule(ctx context.Context, ruleID string) (*RiskRule, error)

	// ListRules 列出所有风控规则
	ListRules(ctx context.Context) ([]*RiskRule, error)

	// Close 关闭规则引擎连接
	Close() error
}

// ==================== 风控规则 ====================

// RiskRule 风控规则
// 定义一条风控规则的触发条件、计算逻辑和处置动作
type RiskRule struct {
	ID          string            // 规则唯一 ID
	Name        string            // 规则名称
	Description string            // 规则描述
	Type        RiskEventType     // 适用的事件类型
	Level       RiskLevel         // 触发后的风险等级
	Score       float64           // 触发后加算的风险分数
	Action      RiskAction        // 触发后的建议动作
	Condition   string            // 触发条件表达式（Flink SQL 或 CEL）
	Window      time.Duration     // 时间窗口（滑动窗口大小）
	Threshold   int               // 阈值（窗口内触发次数）
	Enabled     bool              // 是否启用
	CreatedAt   time.Time         // 创建时间
	UpdatedAt   time.Time         // 更新时间
	Tags        []string          // 标签（用于分类和过滤）
	Metadata    map[string]string // 扩展元数据
}

// NewRiskRule 创建风控规则
func NewRiskRule(id, name string, eventType RiskEventType, level RiskLevel) *RiskRule {
	return &RiskRule{
		ID:        id,
		Name:      name,
		Type:      eventType,
		Level:     level,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Tags:      make([]string, 0),
		Metadata:  make(map[string]string),
	}
}

// WithCondition 设置触发条件表达式
func (rr *RiskRule) WithCondition(condition string) *RiskRule {
	rr.Condition = condition
	return rr
}

// WithWindow 设置时间窗口和阈值
// window: 滑动窗口大小，threshold: 窗口内触发次数阈值
func (rr *RiskRule) WithWindow(window time.Duration, threshold int) *RiskRule {
	rr.Window = window
	rr.Threshold = threshold
	return rr
}

// WithAction 设置建议动作
func (rr *RiskRule) WithAction(action RiskAction) *RiskRule {
	rr.Action = action
	return rr
}

// WithScore 设置风险分数
func (rr *RiskRule) WithScore(score float64) *RiskRule {
	rr.Score = score
	return rr
}

// WithTags 添加标签
func (rr *RiskRule) WithTags(tags ...string) *RiskRule {
	rr.Tags = append(rr.Tags, tags...)
	return rr
}

// ==================== 黑名单管理 ====================

// BlacklistManager 黑名单管理器接口
// 管理黑名单和白名单，支持实时增删和查询
// 黑名单数据可存储在 Redis 中，实现分布式共享
type BlacklistManager interface {
	// AddToBlacklist 添加到黑名单
	// subject: 主体标识（用户 ID / IP / 设备 ID）
	// reason: 拉黑原因
	// ttl: 黑名单有效期（0 表示永久）
	AddToBlacklist(ctx context.Context, subject, reason string, ttl time.Duration) error

	// RemoveFromBlacklist 从黑名单移除
	RemoveFromBlacklist(ctx context.Context, subject string) error

	// IsBlacklisted 检查是否在黑名单中
	IsBlacklisted(ctx context.Context, subject string) (bool, error)

	// AddToWhitelist 添加到白名单
	// 白名单中的主体不受风控规则影响
	AddToWhitelist(ctx context.Context, subject, reason string) error

	// RemoveFromWhitelist 从白名单移除
	RemoveFromWhitelist(ctx context.Context, subject string) error

	// IsWhitelisted 检查是否在白名单中
	IsWhitelisted(ctx context.Context, subject string) (bool, error)

	// ListBlacklist 列出黑名单
	ListBlacklist(ctx context.Context, offset, limit int) ([]*BlacklistEntry, error)

	// Close 关闭管理器
	Close() error
}

// BlacklistEntry 黑名单条目
type BlacklistEntry struct {
	Subject   string    // 主体标识
	Reason    string    // 拉黑原因
	AddedAt   time.Time // 添加时间
	ExpireAt  time.Time // 过期时间（零值表示永久）
	AddedBy   string    // 操作人
}

// IsExpired 判断黑名单条目是否已过期
func (be *BlacklistEntry) IsExpired() bool {
	if be.ExpireAt.IsZero() {
		return false
	}
	return time.Now().After(be.ExpireAt)
}

// ==================== 风控回调 ====================

// RiskCallback 风控回调函数
// 当风控规则触发时调用，用于通知业务系统
type RiskCallback func(assessment *RiskAssessment, event *RiskEvent)

// RiskCallbackRegistry 风控回调注册表
type RiskCallbackRegistry struct {
	callbacks map[RiskLevel][]RiskCallback
}

// NewRiskCallbackRegistry 创建风控回调注册表
func NewRiskCallbackRegistry() *RiskCallbackRegistry {
	return &RiskCallbackRegistry{
		callbacks: make(map[RiskLevel][]RiskCallback),
	}
}

// Register 注册指定风险等级的回调
func (rcr *RiskCallbackRegistry) Register(level RiskLevel, callback RiskCallback) {
	rcr.callbacks[level] = append(rcr.callbacks[level], callback)
}

// Trigger 触发指定风险等级的所有回调
func (rcr *RiskCallbackRegistry) Trigger(assessment *RiskAssessment, event *RiskEvent) {
	callbacks, ok := rcr.callbacks[assessment.Level]
	if !ok {
		return
	}
	for _, cb := range callbacks {
		cb(assessment, event)
	}
}
