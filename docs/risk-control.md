# 实时风控与反黑产

## 🎯 目标

本指南详细介绍 go-casbin 的实时风控与反黑产功能，帮助你实现实时风险评估和反黑产操作

## 📝 风控基础

### 什么是实时风控？

实时风控是一种实时评估和处理风险的机制，通过规则引擎对请求进行实时分析，识别和处理潜在的风险行为

### 反黑产的挑战

- **恶意注册**：批量注册账号
- **暴力破解**：尝试猜测密码
- **刷量作弊**：刷取积分、优惠券
- **爬虫抓取**：大量抓取网站数据
- **恶意攻击**：DDoS 攻击、SQL 注入

## 🔧 风控架构

```
请求 → Enforcer.Enforce() → FlinkRuleEngine.Evaluate() → RiskAssessment
                                     │
                                     ├── 规则匹配（异地登录、高频交易等）
                                     ├── 黑名单检查
                                     └── 风险评分
```

### 核心组件

1. **RiskEvent**：风险事件，包含事件类型、用户、资源等信息
2. **RiskRule**：风险规则，定义风险评估的条件和动作
3. **RiskAssessment**：风险评估结果，包含风险等级和建议动作
4. **FlinkRuleEngine**：规则引擎，执行规则匹配和风险评估

## 🔧 风控事件

### 事件类型

| 事件类型 | 描述 | 示例 |
|---------|------|------|
| `RiskEventLogin` | 登录事件 | 用户登录 |
| `RiskEventRegister` | 注册事件 | 新用户注册 |
| `RiskEventTransaction` | 交易事件 | 支付、转账 |
| `RiskEventAccess` | 访问事件 | API 调用、页面访问 |
| `RiskEventOperation` | 操作事件 | 修改密码、绑定手机 |

### 创建风控事件

```go
import (
    "github.com/kamalyes/go-casbin/policy"
)

// 创建登录事件
event := policy.NewRiskEvent(policy.RiskEventLogin, "user-123", "api/login", "login").
    WithIP("192.168.1.100").
    WithDeviceID("device-abc").
    WithContext("location", "Beijing").
    WithContext("user_agent", "Mozilla/5.0...")

// 创建交易事件
event := policy.NewRiskEvent(policy.RiskEventTransaction, "user-123", "api/pay", "payment").
    WithAmount(1000.0).
    WithCurrency("CNY").
    WithContext("product_id", "prod-456").
    WithContext("payment_method", "alipay")
```

## 🔧 风险规则

### 规则类型

| 规则类型 | 描述 | 示例 |
|---------|------|------|
| `RiskLevelLow` | 低风险 | 轻微异常行为 |
| `RiskLevelMedium` | 中风险 | 可疑行为 |
| `RiskLevelHigh` | 高风险 | 明显恶意行为 |
| `RiskLevelCritical` | 严重风险 | 严重恶意行为 |

### 创建风险规则

```go
import (
    "time"

    "github.com/kamalyes/go-casbin/policy"
)

// 创建异地登录检测规则
rule := policy.NewRiskRule("rule-001", "异地登录检测", policy.RiskEventLogin, policy.RiskLevelHigh).
    WithCondition("ip_location != last_login_location").
    WithWindow(10*time.Minute, 3).  // 10 分钟内 3 次
    WithAction(policy.RiskActionBlock).
    WithScore(80)

// 创建高频交易检测规则
rule := policy.NewRiskRule("rule-002", "高频交易检测", policy.RiskEventTransaction, policy.RiskLevelMedium).
    WithCondition("amount > 5000").
    WithWindow(1*time.Hour, 5).  // 1 小时内 5 次
    WithAction(policy.RiskActionVerify).
    WithScore(60)
```

### 规则条件

| 条件类型 | 描述 | 示例 |
|---------|------|------|
| `ip_location != last_login_location` | 异地登录 | 检测 IP 地址变更 |
| `device_id != last_device_id` | 设备变更 | 检测设备变更 |
| `amount > threshold` | 大额交易 | 检测大额交易 |
| `frequency > limit` | 高频操作 | 检测操作频率 |
| `user_agent in blacklist` | 可疑用户代理 | 检测恶意爬虫 |
| `ip in blacklist` | 黑名单 IP | 检测黑名单 IP |

## 🔧 风险评估

### 评估动作

| 动作 | 描述 | 适用场景 |
|------|------|----------|
| `RiskActionAllow` | 允许通过 | 低风险 |
| `RiskActionVerify` | 需要二次验证 | 中风险 |
| `RiskActionBlock` | 直接拦截 | 高风险 |
| `RiskActionQuarantine` | 隔离观察 | 可疑风险 |

### 评估结果

```go
import (
    "context"

    "github.com/kamalyes/go-casbin/policy"
)

// 评估风控（需要实现 FlinkRuleEngine 接口）
assessment, err := flinkEngine.Evaluate(ctx, event)
if err != nil {
    log.Error("风控评估失败: %v", err)
    return
}

// 根据评估结果决策
switch assessment.Action {
case policy.RiskActionAllow:
    // 允许通过
    log.Info("风控评估通过", "user", event.UserID, "score", assessment.Score)
case policy.RiskActionVerify:
    // 需要二次验证（短信/邮箱）
    log.Warn("需要二次验证", "user", event.UserID, "score", assessment.Score)
    sendVerificationCode(event.UserID)
case policy.RiskActionBlock:
    // 直接拦截
    log.Error("风控拦截", "user", event.UserID, "score", assessment.Score, "reasons", assessment.Reasons)
    return errors.New("操作被风控拦截")
case policy.RiskActionQuarantine:
    // 隔离观察
    log.Warn("隔离观察", "user", event.UserID, "score", assessment.Score)
    addToQuarantineList(event.UserID)
}
```

## 🔧 黑名单管理

### 黑名单操作

```go
import (
    "context"
    "time"

    "github.com/kamalyes/go-casbin/policy"
)

// 添加到黑名单（TTL 24 小时）
err := blacklistMgr.AddToBlacklist(ctx, "user-456", "异常登录", 24*time.Hour)
if err != nil {
    log.Error("添加黑名单失败: %v", err)
}

// 检查是否在黑名单中
blocked, err := blacklistMgr.IsBlacklisted(ctx, "user-456")
if err != nil {
    log.Error("检查黑名单失败: %v", err)
} else if blocked {
    log.Warn("用户在黑名单中", "user", "user-456")
    return errors.New("用户被黑名单拦截")
}

// 从黑名单移除
err := blacklistMgr.RemoveFromBlacklist(ctx, "user-456")
if err != nil {
    log.Error("移除黑名单失败: %v", err)
}

// 添加到白名单（白名单不受风控规则影响）
err := blacklistMgr.AddToWhitelist(ctx, "trusted-service", "内部服务")
if err != nil {
    log.Error("添加白名单失败: %v", err)
}

// 检查是否在白名单中
whitelisted, err := blacklistMgr.IsWhitelisted(ctx, "trusted-service")
if err != nil {
    log.Error("检查白名单失败: %v", err)
} else if whitelisted {
    log.Info("服务在白名单中", "service", "trusted-service")
    // 跳过风控检查
}
```

### 黑名单类型

| 类型 | 描述 | 示例 |
|------|------|------|
| `BlacklistTypeUser` | 用户黑名单 | 恶意用户 |
| `BlacklistTypeIP` | IP 黑名单 | 恶意 IP |
| `BlacklistTypeDevice` | 设备黑名单 | 恶意设备 |
| `BlacklistTypeUA` | 用户代理黑名单 | 恶意爬虫 |

## 🔧 规则引擎集成

### 实现 FlinkRuleEngine 接口

```go
import (
    "context"

    "github.com/kamalyes/go-casbin/policy"
)

// FlinkRuleEngine 规则引擎接口
type FlinkRuleEngine interface {
    // Evaluate 评估风险事件
    Evaluate(ctx context.Context, event *policy.RiskEvent) (*policy.RiskAssessment, error)
    // SubmitRule 提交规则
    SubmitRule(ctx context.Context, rule *policy.RiskRule) error
    // RemoveRule 删除规则
    RemoveRule(ctx context.Context, ruleID string) error
    // GetRules 获取所有规则
    GetRules(ctx context.Context) ([]*policy.RiskRule, error)
}

// 实现规则引擎
func (re *RuleEngine) Evaluate(ctx context.Context, event *policy.RiskEvent) (*policy.RiskAssessment, error) {
    // 1. 检查白名单
    if re.isWhitelisted(event) {
        return &policy.RiskAssessment{
            Action: policy.RiskActionAllow,
            Score:  0,
            Reasons: []string{"白名单"},
        }, nil
    }

    // 2. 检查黑名单
    if re.isBlacklisted(event) {
        return &policy.RiskAssessment{
            Action: policy.RiskActionBlock,
            Score:  100,
            Reasons: []string{"黑名单"},
        }, nil
    }

    // 3. 执行规则匹配
    score := 0
    var reasons []string
    
    for _, rule := range re.rules {
        if rule.EventType == event.Type && re.matchRule(rule, event) {
            score += rule.Score
            reasons = append(reasons, rule.Description)
        }
    }

    // 4. 生成评估结果
    action := policy.RiskActionAllow
    if score >= 80 {
        action = policy.RiskActionBlock
    } else if score >= 60 {
        action = policy.RiskActionVerify
    } else if score >= 40 {
        action = policy.RiskActionQuarantine
    }

    return &policy.RiskAssessment{
        Action:  action,
        Score:   score,
        Reasons: reasons,
    }, nil
}
```

## 🔧 与 Enforcer 集成

### 自定义 Enforcer 方法

```go
import (
    "context"

    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-casbin/policy"
)

// EnforceWithRisk 带风控的权限检查
func (e *Enforcer) EnforceWithRisk(ctx context.Context, flinkEngine policy.FlinkRuleEngine, event *policy.RiskEvent, args ...interface{}) (bool, *policy.RiskAssessment, error) {
    // 1. 执行风控评估
    assessment, err := flinkEngine.Evaluate(ctx, event)
    if err != nil {
        return false, nil, err
    }

    // 2. 根据风控结果决策
    switch assessment.Action {
    case policy.RiskActionBlock:
        return false, assessment, nil
    case policy.RiskActionVerify:
        // 需要二次验证，这里简化处理
        return false, assessment, nil
    case policy.RiskActionQuarantine:
        // 隔离观察，这里简化处理
        return false, assessment, nil
    }

    // 3. 执行正常的权限检查
    ok, err := e.EnforceWithContext(ctx, args...)
    return ok, assessment, err
}
```

### 使用示例

```go
import (
    "context"

    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-casbin/policy"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 创建执行器
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 创建风控事件
    event := policy.NewRiskEvent(policy.RiskEventLogin, "alice", "api/login", "login").
        WithIP("192.168.1.100").
        WithDeviceID("device-abc")

    // 执行带风控的权限检查
    ok, assessment, err := e.EnforceWithRisk(ctx, flinkEngine, event, "alice", "data1", "read")
    if err != nil {
        log.Error("权限检查失败: %v", err)
        return
    }

    log.InfoKV("权限检查结果", "ok", ok, "risk_score", assessment.Score, "risk_action", assessment.Action, "risk_reasons", assessment.Reasons)
}
```

## 🔍 风控最佳实践

### 1. 规则设计

- **分层规则**：设计多层级的规则体系
- **阈值调整**：根据业务场景调整规则阈值
- **规则组合**：使用多个规则组合评估风险
- **动态调整**：根据实际情况动态调整规则

### 2. 数据收集

- **用户行为**：收集用户的登录、交易等行为数据
- **设备信息**：收集设备 ID、IP 地址等信息
- **环境信息**：收集地理位置、网络环境等信息
- **历史数据**：分析历史数据，发现风险模式

### 3. 系统集成

- **实时处理**：使用 Flink 等流处理框架实时处理
- **批处理**：定期批处理历史数据，更新规则
- **机器学习**：使用机器学习模型识别风险模式
- **告警机制**：设置合理的告警机制

### 4. 性能优化

- **缓存**：缓存规则和黑名单，提高查询性能
- **异步处理**：将非实时操作异步处理
- **批量评估**：批量处理风险事件
- **降级策略**：当系统负载高时，启用降级策略

### 5. 安全性

- **数据加密**：对敏感数据进行加密存储
- **访问控制**：限制风控系统的访问权限
- **审计日志**：记录所有风控操作的审计日志
- **合规性**：确保风控措施符合法律法规

## ❓ 常见问题

### Q: 如何平衡风控的严格性和用户体验？

A: 
- **分层风控**：根据风险等级采取不同措施
- **白名单**：为可信用户和场景设置白名单
- **渐进式验证**：从轻度验证到重度验证
- **用户教育**：向用户解释风控措施的必要性

### Q: 如何处理误判？

A: 
- **申诉机制**：提供用户申诉渠道
- **人工审核**：对可疑案例进行人工审核
- **规则调整**：根据误判情况调整规则
- **反馈机制**：收集误判反馈，持续优化

### Q: 如何应对新型黑产攻击？

A: 
- **持续监控**：监控新的攻击模式
- **规则更新**：及时更新规则以应对新攻击
- **威胁情报**：订阅威胁情报，了解最新攻击手法
- **安全合作**：与安全社区合作，共享攻击信息

### Q: 如何评估风控系统的效果？

A: 
- **准确率**：正确识别风险的比例
- **误报率**：误将正常行为识别为风险的比例
- **漏报率**：未能识别实际风险的比例
- **响应时间**：风控评估的响应时间
- **阻断效果**：风控措施的实际阻断效果

## 🚀 下一步

- 查看 [示例代码](/examples/) 学习实际使用场景
- 阅读 [API 文档](/docs/api.md) 了解详细 API
- 探索 [企业级部署指南](/docs/enterprise-deployment.md) 掌握部署最佳实践