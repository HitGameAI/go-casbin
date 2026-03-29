# 策略管理指南

## 🎯 目标

本指南详细介绍 go-casbin 的策略管理功能，帮助你掌握策略的加载、保存、添加、删除和更新操作

## 📝 策略基础

### 策略定义

策略是权限规则的集合，定义了谁（subject）对什么资源（object）可以执行什么操作（action）

### 策略文件格式

策略通常存储在 CSV 文件中，格式如下：

```csv
# 基本策略
p, alice, data1, read
p, bob, data2, write

# 带效果的策略
p, eve, data3, read, deny

# 角色继承
g, alice, admin
```

### 策略存储后端

go-casbin 支持多种存储后端：

1. **文件存储**：CSV 文件
2. **内存存储**：内存中的策略集合
3. **ORM 存储**：MySQL、PostgreSQL、SQLite 等关系型数据库
4. **Redis 存储**：Redis 缓存
5. **自定义存储**：实现 Adapter 接口

## 🔧 策略管理 API

### 1. 加载策略

```go
// 从文件加载策略
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
)

// 从适配器加载策略（如 ORM、Redis）
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithAdapter(ormAdapter),
)

// 手动加载策略
err := e.LoadPolicy()
```

### 2. 保存策略

```go
// 自动保存（创建执行器时启用）
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
    enforcer.WithAutoSave(true),
)

// 手动保存策略
err := e.SavePolicy()
```

### 3. 添加策略

```go
// 添加单条策略
err := e.AddPolicy("alice", "data3", "read")

// 批量添加策略
err := e.AddPolicies([][]string{
    {"alice", "data3", "write"},
    {"bob", "data3", "read"},
})

// 添加带域的策略（多租户）
err := e.AddPolicy("alice", "tenant1", "data1", "write")
```

### 4. 删除策略

```go
// 删除单条策略
err := e.RemovePolicy("alice", "data3", "read")

// 批量删除策略
err := e.RemovePolicies([][]string{
    {"alice", "data3", "write"},
    {"bob", "data3", "read"},
})

// 删除带域的策略
err := e.RemovePolicy("alice", "tenant1", "data1", "write")
```

### 5. 更新策略

```go
// 更新策略
err := e.UpdatePolicy(
    []string{"alice", "data1", "read"},  // 旧策略
    []string{"alice", "data1", "write"}, // 新策略
)

// 更新带域的策略
err := e.UpdatePolicy(
    []string{"alice", "tenant1", "data1", "read"},
    []string{"alice", "tenant1", "data1", "write"},
)
```

### 6. 过滤策略

```go
// 获取过滤后的策略
// 格式：GetFilteredPolicy(section, fieldIndex, ...fieldValues)
policies := e.GetFilteredPolicy("p", 0, "alice") // 获取 alice 的所有策略

// 获取带域的过滤策略
policies := e.GetFilteredPolicy("p", 1, "tenant1") // 获取 tenant1 的所有策略
```

### 7. 角色管理

```go
// 添加角色继承
err := e.AddRoleForUser("alice", "admin")

// 删除角色继承
err := e.DeleteRoleForUser("alice", "admin")

// 获取用户的角色
roles := e.GetRolesForUser("alice")

// 获取角色的用户
users := e.GetUsersForRole("admin")

// 检查角色继承关系
hasRole := e.HasRoleForUser("alice", "admin")

// 多租户角色管理
roles := e.GetRolesForUserInDomain("alice", "tenant1")
err := e.AddRoleForUserInDomain("alice", "admin", "tenant1")
```

### 8. 权限查询

```go
// 获取所有策略
allPolicies := e.GetPolicy()

// 获取用户的权限
perms := e.GetPermissionsForUser("alice")

// 获取带域的用户权限
perms := e.GetPermissionsForUserInDomain("alice", "tenant1")

// 获取角色的权限
rolePerms := e.GetPermissionsForUser("admin")

// 检查权限
hasPerm, err := e.HasPermissionForUser("alice", "data1", "read")
```

## 🎨 高级策略管理

### 1. 策略缓存

go-casbin 使用 `syncx.Map` 实现策略缓存，提高权限检查性能：

```go
// 启用缓存（默认启用）
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
)

// 缓存会自动在策略变更时更新
```

### 2. 策略监听器

监控策略文件变更，实现热更新：

```go
// 创建执行器时自动启用文件监听器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
)

// 当策略文件变更时，会自动重载
```

### 3. 分布式策略同步

在分布式部署中，使用 Pub/Sub 实现策略同步：

```go
import (
    redisadapter "github.com/kamalyes/go-casbin-redis-adapter"
    "github.com/redis/go-redis/v9"
)

// 创建 Redis 通知器
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
notifier, _ := redisadapter.NewRedisNotifier(rdb,
    policy.WithChannel("casbin:policy:changes"),
    policy.WithSource("node-1"),
)

// 创建执行器并集成通知器
e, _ := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
    enforcer.WithNotifier(notifier),
)

// A 节点修改策略 → 自动通知 B/C/D 节点
_ = e.AddPolicy("alice", "data3", "read")
```

### 4. 策略效果评估

自定义策略效果评估逻辑：

```go
// 标准白名单模式
// e = some(where (p.eft == allow))

// 标准黑名单模式
// e = !some(where (p.eft == deny))

// 严格模式
// e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
```

## 🔍 策略解析

### 1. 策略行解析

go-casbin 支持智能解析策略行，处理括号内的逗号：

```csv
# 复杂表达式，括号内的逗号会被正确处理
p, r.sub in ("alice", "bob"), data4, read
p, r.sub == "admin" || r.sub.Role == "manager", data5, write
```

### 2. 动态策略

使用 ABAC 规则策略模式，实现动态策略：

```csv
# 基于用户属性的动态策略
p, r.sub.Role == "admin", data1, write
p, r.sub.Age > 18, data2, read
p, r.sub.Department == r.obj.Department, data3, read
```

## 📝 最佳实践

### 1. 策略组织

- **按功能分类**：将不同功能的策略放在不同文件中
- **使用注释**：在策略文件中添加注释，说明策略的用途
- **版本控制**：将策略文件纳入版本控制，跟踪变更

### 2. 性能优化

- **批量操作**：使用批量 API 减少数据库操作次数
- **合理使用缓存**：对于频繁访问的策略，依赖缓存提高性能
- **定期清理**：定期清理过期或无用的策略

### 3. 安全性

- **最小权限原则**：只授予必要的权限
- **定期审计**：定期检查和审计策略
- **避免硬编码**：使用配置文件管理策略，避免在代码中硬编码

### 4. 多租户策略管理

- **域隔离**：使用 RBAC with Domains 模型实现租户隔离
- **独立存储**：为每个租户使用独立的存储后端
- **策略前缀**：使用前缀区分不同租户的策略

## ❓ 常见问题

### Q: 如何处理策略冲突？

A: 使用策略效果评估器，定义冲突解决规则：

- **白名单模式**：任一策略允许则允许
- **黑名单模式**：没有策略拒绝则允许
- **严格模式**：有允许且无拒绝才允许
- **优先级模式**：按优先级决定最终结果

### Q: 如何实现策略版本管理？

A: 
- 将策略文件纳入版本控制
- 使用数据库存储并添加版本字段
- 实现策略变更日志，记录每次修改

### Q: 如何处理大量策略？

A: 
- 使用 ORM 或 Redis 存储，提高查询性能
- 合理使用缓存，减少数据库访问
- 采用分层策略，利用角色继承减少重复策略

### Q: 如何实现策略的灰度发布？

A: 
- 使用多个策略文件，逐步切换
- 实现策略的 A/B 测试
- 使用特性标志控制策略的启用/禁用

## 🚀 下一步

- 查看 [角色管理指南](role-management.md) 深入理解角色继承
- 阅读 [多租户指南](multitenancy.md) 掌握多租户隔离方案
- 探索 [适配器使用指南](adapters.md) 了解各种存储适配器