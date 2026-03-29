# 入门指南

## 🎯 目标

本指南将帮助你快速上手 go-casbin 企业级权限管理系统，从安装到基本使用，循序渐进地掌握核心功能

## 🚀 快速开始

### 1. 基本 ACL 示例

ACL（Access Control List）是最简单的权限模型，直接定义用户对资源的操作权限

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    // 创建日志器
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 创建执行器
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/acl_model.conf"),
        enforcer.WithPolicyPath("resources/acl_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 权限检查
    check(log, e, "alice", "data1", "read")   // 应该允许
    check(log, e, "alice", "data1", "write")  // 应该允许
    check(log, e, "bob", "data2", "read")     // 应该允许
    check(log, e, "bob", "data1", "read")     // 应该拒绝
}

func check(log logger.ILogger, e *enforcer.Enforcer, sub, obj, act string) {
    ok, err := e.Enforce(sub, obj, act)
    if err != nil {
        log.ErrorKV("权限检查异常", "sub", sub, "obj", obj, "act", act, "error", err.Error())
        return
    }
    if ok {
        log.InfoKV("✅ 允许访问", "sub", sub, "obj", obj, "act", act)
    } else {
        log.WarnKV("❌ 拒绝访问", "sub", sub, "obj", obj, "act", act)
    }
}
```

### 2. RBAC 示例

RBAC（Role-Based Access Control）基于角色的访问控制，通过角色继承实现权限管理

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // alice 继承 admin 角色，应该有所有权限
    check(log, e, "alice", "data1", "read")    // 允许
    check(log, e, "alice", "data1", "write")   // 允许
    check(log, e, "alice", "data2", "read")    // 允许
    check(log, e, "alice", "data2", "write")   // 允许

    // bob 继承 user 角色，只有 read 权限
    check(log, e, "bob", "data1", "read")      // 允许
    check(log, e, "bob", "data1", "write")     // 拒绝
}
```

### 3. ABAC 示例

ABAC（Attribute-Based Access Control）基于属性的访问控制，通过资源属性和请求参数进行权限判断

#### 3.1 属性匹配模式

不需要策略文件，直接基于资源属性判断

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

// Resource 带属性的资源对象
type Resource struct {
    Name  string
    Owner string
}

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/abac_model.conf"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    data1 := Resource{Name: "data1", Owner: "alice"}
    data2 := Resource{Name: "data2", Owner: "bob"}

    // alice 是 data1 的所有者，应该允许
    check(log, e, "alice", data1, "read")  // 允许
    // bob 不是 data1 的所有者，应该拒绝
    check(log, e, "bob", data1, "read")    // 拒绝
    // bob 是 data2 的所有者，应该允许
    check(log, e, "bob", data2, "write")   // 允许
}
```

#### 3.2 规则策略模式

使用独立的 CSV 策略文件，通过 `eval()` 动态求值

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/abac_rule_model.conf"),
        enforcer.WithPolicyPath("resources/abac_rule_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 等于判断：r.sub == "alice"
    check(log, e, "alice", "data1", "read")   // 允许
    // 不等于判断：r.sub != "eve"
    check(log, e, "alice", "data3", "read")   // 允许
    check(log, e, "eve", "data3", "read")     // 拒绝
    // 包含判断：r.sub in ("alice", "bob")
    check(log, e, "alice", "data4", "read")   // 允许
    check(log, e, "bob", "data4", "read")     // 允许
    check(log, e, "eve", "data4", "read")     // 拒绝
}
```

### 4. 多租户 RBAC 示例

多租户场景下，同一用户在不同租户中拥有不同角色

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

    // 角色管理 API
    roles := e.GetRolesForUserInDomain("alice", "tenant1")
    log.InfoKV("alice 在 tenant1 中的角色", "roles", roles)

    perms := e.GetPermissionsForUserInDomain("alice", "tenant2")
    log.InfoKV("alice 在 tenant2 中的权限", "permissions", perms)
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

## 📁 目录结构

```
go-casbin/
├── enforcer/         # 核心执行器
├── model/            # 模型管理
├── policy/           # 策略管理
├── role/             # 角色管理
├── config/           # 配置管理
├── monitor/          # 监控管理
├── errors/           # 错误定义
├── resources/        # 资源文件
│   ├── acl_model.conf
│   ├── rbac_model.conf
│   ├── abac_model.conf
│   └── ...
├── examples/         # 示例代码
├── docs/             # 文档
├── go.mod
└── README.md
```

## 🎨 配置选项

go-casbin 支持链式调用的配置选项：

```go
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
    enforcer.WithLogger(log),
    enforcer.WithAutoSave(true),
    enforcer.WithEnabled(true),
)
```

## 📚 后续学习

- [模型配置指南](model-config.md) - 详细了解模型配置语法
- [策略管理指南](policy-management.md) - 学习如何管理策略
- [角色管理指南](role-management.md) - 深入理解角色继承
- [多租户指南](multitenancy.md) - 掌握多租户隔离方案
- [适配器使用指南](adapters.md) - 了解各种存储适配器
- [高级特性指南](advanced-features.md) - 探索熔断、重试等高级特性

## ❓ 常见问题

### Q: 为什么我的权限检查总是返回 false？

A: 可能的原因：
- 模型配置错误（matcher 表达式不正确）
- 策略文件路径错误
- 策略规则格式不正确
- 角色继承关系未正确定义

### Q: 如何动态添加策略？

A: 使用 `AddPolicy` 方法：

```go
err := e.AddPolicy("alice", "data3", "read")
```

### Q: 如何实现多租户隔离？

A: 使用 RBAC with Domains 模型，在策略中添加域字段：

```csv
p, admin, tenant1, data1, read
g, alice, admin, tenant1
```

### Q: 支持哪些存储后端？

A: 支持：
- 文件存储（CSV）
- 内存存储
- ORM 存储（MySQL/PostgreSQL/SQLite）
- Redis 存储
- 自定义存储（实现 Adapter 接口）

## 🚀 下一步

- 查看 [examples](/examples/) 目录中的完整示例
- 阅读 [模型配置指南](model-config.md) 了解更多配置选项
- 探索 [高级特性指南](advanced-features.md) 掌握企业级功能