# 多租户指南

## 🎯 目标

本指南详细介绍 go-casbin 的多租户支持，帮助你实现不同租户之间的权限隔离

## 📝 多租户基础

### 什么是多租户？

多租户是一种软件架构模式，允许多个租户（客户）共享同一套系统，同时保持数据和配置的隔离

### 多租户权限隔离的挑战

- **数据隔离**：不同租户的数据需要隔离
- **权限隔离**：不同租户的权限规则需要隔离
- **配置隔离**：不同租户的配置需要隔离
- **性能隔离**：一个租户的操作不应影响其他租户

## 🔧 多租户实现方案

### 1. RBAC with Domains 模型

这是 go-casbin 推荐的多租户实现方案，通过域（domain）字段实现隔离

#### 模型配置

```ini
# resources/rbac_with_domains_model.conf
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

#### 策略配置

```csv
# resources/rbac_with_domains_policy.csv
p, admin, tenant1, data1, read
p, admin, tenant1, data1, write
p, admin, tenant2, data2, read
p, viewer, tenant2, data2, read
g, alice, admin, tenant1
g, alice, viewer, tenant2
g, bob, viewer, tenant1
```

#### 使用示例

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_with_domains_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_with_domains_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // alice 在 tenant1 中是 admin，应该有所有权限
    check(log, e, "alice", "tenant1", "data1", "read")   // 允许
    check(log, e, "alice", "tenant1", "data1", "write")  // 允许

    // alice 在 tenant2 中是 viewer，只有 read 权限
    check(log, e, "alice", "tenant2", "data2", "read")   // 允许
    check(log, e, "alice", "tenant2", "data2", "write")  // 拒绝

    // bob 只在 tenant1 中是 viewer
    check(log, e, "bob", "tenant1", "data1", "read")     // 允许
    check(log, e, "bob", "tenant2", "data2", "read")     // 拒绝
}

func check(log logger.ILogger, e *enforcer.Enforcer, sub, dom, obj, act string) {
    ok, err := e.Enforce(sub, dom, obj, act)
    if err != nil {
        log.ErrorKV("权限检查异常", "sub", sub, "dom", dom, "obj", obj, "act", act, "error", err.Error())
        return
    }
    if ok {
        log.InfoKV("✅ 允许访问", "sub", sub, "dom", dom, "obj", obj, "act", act)
    } else {
        log.WarnKV("❌ 拒绝访问", "sub", sub, "dom", dom, "obj", obj, "act", act)
    }
}
```

### 2. 租户工厂模式

为每个租户创建独立的 Enforcer 实例，实现完全隔离

#### 实现示例

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    gormadapter "github.com/kamalyes/go-casbin-gorm-adapter"
    redisadapter "github.com/kamalyes/go-casbin-redis-adapter"
    "github.com/kamalyes/go-casbin/policy"
    "github.com/kamalyes/go-logger"
    "github.com/redis/go-redis/v9"
    "gorm.io/gorm"
)

// NewTenantEnforcer 为每个租户创建独立的 Enforcer
func NewTenantEnforcer(tenantID string, db *gorm.DB, rdb *redis.Client, log logger.ILogger) (*enforcer.Enforcer, error) {
    // 1. ORM 适配器：每个租户独立表
    ormAdapter, err := gormadapter.NewAdapterByDB(db,
        gormadapter.WithTableName("casbin_rule_"+tenantID),
        gormadapter.WithLogger(log),
    )
    if err != nil {
        return nil, err
    }

    // 2. Redis 通知器：每个租户独立频道
    notifier, err := redisadapter.NewRedisNotifier(rdb,
        policy.WithChannel("casbin:"+tenantID+":policy:changes"),
        policy.WithSource(tenantID+"-node-1"),
    )
    if err != nil {
        return nil, err
    }

    // 3. 创建执行器
    return enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_with_domains_model.conf"),
        enforcer.WithAdapter(ormAdapter),
        enforcer.WithNotifier(notifier),
        enforcer.WithLogger(log),
        enforcer.WithAutoSave(true),
        enforcer.WithEnabled(true),
    )
}

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)
    // 初始化数据库连接...

    // 为每个租户创建独立的 Enforcer
    e1, _ := NewTenantEnforcer("tenant1", db, rdb, log)
    e2, _ := NewTenantEnforcer("tenant2", db, rdb, log)

    // 租户 1 的权限检查
    ok, _ := e1.Enforce("alice", "tenant1", "data1", "read")

    // 租户 2 的权限检查
    ok, _ = e2.Enforce("bob", "tenant2", "data2", "write")
}
```

### 3. 域机制扩展

除了租户（tenant）维度，域机制还支持更细粒度的数据权限隔离：

#### 平台维度

```csv
p, admin, platform:web, data1, read
p, admin, platform:mobile, data2, read
g, alice, admin, platform:web
g, alice, viewer, platform:mobile
```

#### 地区维度

```csv
p, admin, region:cn-east, data1, read
p, admin, region:us-west, data2, read
g, alice, admin, region:cn-east
g, bob, admin, region:us-west
```

#### 组合维度

```csv
p, admin, tenant1:platform:web:region:cn-east, data1, read
g, alice, admin, tenant1:platform:web:region:cn-east
```

## 🎨 多租户隔离策略

### 1. 模型隔离

为每个租户使用不同的模型配置：

```
resources/
├── tenant1_model.conf
├── tenant2_model.conf
└── ...
```

### 2. 策略隔离

为每个租户使用独立的策略文件：

```
resources/
├── tenant1_policy.csv
├── tenant2_policy.csv
└── ...
```

### 3. 数据库隔离

为每个租户使用独立的数据库表：

```go
ormAdapter, _ := gormadapter.NewAdapterByDB(db,
    gormadapter.WithTableName("casbin_rule_tenant1"),
)
```

### 4. Redis 隔离

为每个租户使用独立的 Redis Key 前缀：

```go
redisAdapter, _ := redisadapter.NewRedisAdapter(rdb,
    redisadapter.WithKeyPrefix("tenant1:casbin:"),
)
```

### 5. 频道隔离

为每个租户使用独立的 Pub/Sub 频道：

```go
notifier, _ := redisadapter.NewRedisNotifier(rdb,
    policy.WithChannel("casbin:tenant1:policy:changes"),
)
```

### 6. 执行器隔离

为每个租户创建独立的 Enforcer 实例：

```go
tenant1Enforcer, _ := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/tenant1_model.conf"),
    enforcer.WithPolicyPath("resources/tenant1_policy.csv"),
)

tenant2Enforcer, _ := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/tenant2_model.conf"),
    enforcer.WithPolicyPath("resources/tenant2_policy.csv"),
)
```

## 🔍 多租户最佳实践

### 1. 架构设计

- **租户识别**：使用请求上下文或令牌识别租户
- **路由隔离**：为不同租户提供不同的 API 路由
- **中间件**：使用中间件处理租户识别和权限检查
- **缓存策略**：为每个租户使用独立的缓存

### 2. 性能优化

- **连接池**：为每个租户使用独立的数据库连接池
- **缓存共享**：合理共享缓存，避免重复缓存
- **批量操作**：使用批量 API 减少数据库操作
- **异步处理**：将非实时操作异步处理

### 3. 安全性

- **租户隔离**：确保一个租户无法访问其他租户的数据
- **权限审计**：定期审计租户权限
- **数据加密**：对租户数据进行加密存储
- **访问控制**：实现细粒度的访问控制

### 4. 运维管理

- **租户生命周期**：管理租户的创建、修改和删除
- **资源限制**：为每个租户设置资源使用限制
- **监控告警**：监控每个租户的系统使用情况
- **备份恢复**：为每个租户提供独立的备份和恢复机制

## ❓ 常见问题

### Q: 如何处理跨租户的权限？

A: 使用共享域或全局域：

```csv
p, admin, global, data_shared, read
g, alice, admin, global
```

### Q: 如何实现租户管理员？

A: 在每个租户中创建 admin 角色：

```csv
p, admin, tenant1, *, *  # 租户 1 的管理员可以访问所有资源
g, alice, admin, tenant1
```

### Q: 如何处理租户间的资源共享？

A: 使用资源共享策略：

```csv
p, shared, tenant1, data_shared, read
p, shared, tenant2, data_shared, read
g, alice, shared, tenant1
g, bob, shared, tenant2
```

### Q: 如何实现多租户的权限模板？

A: 创建租户模板，批量应用：

```go
// 定义租户模板
func createTenantTemplate(tenantID string) [][]string {
    return [][]string{
        {"admin", tenantID, "data1", "read"},
        {"admin", tenantID, "data1", "write"},
        {"user", tenantID, "data1", "read"},
    }
}

// 应用模板
policy := createTenantTemplate("tenant1")
e.AddPolicies(policy)
```

## 🚀 下一步

- 查看 [适配器使用指南](adapters.md) 了解各种存储适配器
- 阅读 [高级特性指南](advanced-features.md) 掌握企业级功能
- 探索 [实时风控与反黑产](risk-control.md) 了解风控功能