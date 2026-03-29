# 快速开始 - 一步一步教你使用 go-casbin

## 🎯 目标

本指南将通过一个具体的示例，一步一步教你如何安装、配置和使用 go-casbin，让你快速上手企业级权限管理系统

## 📦 步骤 1：安装 Go 环境

如果还没有安装 Go，请先安装：

1. 访问 [Go 官网](https://golang.org/dl/) 下载适合你操作系统的安装包
2. 按照安装向导完成安装
3. 验证安装是否成功：

```bash
go version
```

## 📦 步骤 2：创建项目目录

```bash
# 创建项目目录
mkdir my-casbin-project
cd my-casbin-project

# 初始化 Go 模块
go mod init my-casbin-project
```

## 📦 步骤 3：安装 go-casbin

```bash
go get github.com/kamalyes/go-casbin
```

## 📦 步骤 4：创建模型和策略文件

### 创建资源目录

```bash
mkdir resources
```

### 创建 RBAC 模型文件

创建 `resources/rbac_model.conf` 文件，内容如下：

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

### 创建 RBAC 策略文件

创建 `resources/rbac_policy.csv` 文件，内容如下：

```csv
p, admin, data1, read
p, admin, data1, write
p, admin, data2, read
p, admin, data2, write
p, user, data1, read
g, alice, admin
g, bob, user
```

## 📦 步骤 5：创建主程序

创建 `main.go` 文件，内容如下：

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    // 创建日志器
    log := logger.NewLogger().
        WithLevel(logger.INFO).
        WithShowCaller(true)

    // 创建执行器
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    log.InfoMsg("=== RBAC 权限检查示例 ===")
    
    // 检查 alice 的权限（alice 是 admin 角色）
    check(log, e, "alice", "data1", "read")   // 应该允许
    check(log, e, "alice", "data1", "write")  // 应该允许
    check(log, e, "alice", "data2", "read")   // 应该允许
    check(log, e, "alice", "data2", "write")  // 应该允许

    // 检查 bob 的权限（bob 是 user 角色）
    check(log, e, "bob", "data1", "read")     // 应该允许
    check(log, e, "bob", "data1", "write")    // 应该拒绝
    check(log, e, "bob", "data2", "read")     // 应该拒绝

    // 角色管理 API
    log.InfoMsg("=== 角色管理示例 ===")
    roles := e.GetRolesForUser("alice")
    log.InfoKV("alice 的角色", "roles", roles)

    perms := e.GetPermissionsForUser("admin")
    log.InfoKV("admin 角色的权限", "permissions", perms)

    // 动态添加策略
    log.InfoMsg("=== 动态添加策略示例 ===")
    err = e.AddPolicy("bob", "data2", "read")
    if err != nil {
        log.ErrorKV("添加策略失败", "error", err.Error())
    } else {
        log.InfoMsg("成功添加策略: bob, data2, read")
    }

    // 再次检查 bob 的权限
    check(log, e, "bob", "data2", "read")     // 现在应该允许
}

// check 检查权限并输出结果
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

## 📦 步骤 6：运行程序

```bash
go run main.go
```

### 预期输出

```
2026/3/29 20:19:05 ℹ️ [INFO] [model.go:76:LoadFromPath] Model loaded from file {path: resou
rces/rbac_model.conf, sections: 5}
2026/3/29 20:19:05 ℹ️ [INFO] [policy.go:60:LoadPolicy] Policy loaded {count: 9}
2026/3/29 20:19:05 ℹ️ [INFO] [manager.go:68:AddLink] Role link added {name1: alice, name2: 
admin}
2026/3/29 20:19:05 ℹ️ [INFO] [manager.go:68:AddLink] Role link added {name1: bob, name2: vi
ewer}
2026/3/29 20:19:05 ℹ️ [INFO] [enforcer.go:103:func1] Enforcer state changed {from: disabled
, to: ready}
2026/3/29 20:19:05 ℹ️ [INFO] [enforcer.go:182:NewEnforcer] Enforcer created successfully {m
odel_sections: 5, auto_save: true, enabled: true}
2026/3/29 20:19:05 ℹ️ [INFO] [proc.go:285:main] === RBAC 权限检查示例 ===
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: alice, obj: data1, act: read}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: alice, obj: data1, act: write}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: alice, obj: data2, act: read}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: alice, obj: data2, act: write}
2026/3/29 20:19:05 ⚠️ [WARN] [main.go:68:check] ❌ 拒绝访问 {sub: bob, obj: data1, act: read}
2026/3/29 20:19:05 ⚠️ [WARN] [main.go:68:check] ❌ 拒绝访问 {sub: bob, obj: data1, act: write}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: bob, obj: data2, act: read2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: bob, obj: data2, act: read}
2026/3/29 20:19:05 ℹ️ [INFO] [proc.go:285:main] === 角色管理示例 ===
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:40:main] alice 的角色 {roles: [admin]}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:43:main] admin 角色的权限 {permissions: [[admin data1
 read] [admin data1 write] [admin data2 read] [admin data2 write]]}
2026/3/29 20:19:05 ℹ️ [INFO] [proc.go:285:main] === 动态添加策略示例 ===
2026/3/29 20:19:05 ❌ [ERROR] [main.go:49:main] 添加策略失败 {error: policy already exists: ob, data2, read}
bob, data2, read}
2026/3/29 20:19:05 ℹ️ [INFO] [main.go:66:check] ✅ 允许访问 {sub: bob, obj: data2, act: read}
```

## 📦 步骤 7：理解代码

### 1. 模型配置

- **request_definition**：定义请求参数 `sub`（主体）、`obj`（客体）、`act`（操作）
- **policy_definition**：定义策略参数，与请求参数对应
- **role_definition**：定义角色继承关系 `g = _, _`（用户 -> 角色）
- **policy_effect**：定义策略效果，`some(where (p.eft == allow))` 表示任一策略允许则允许
- **matchers**：定义匹配逻辑，`g(r.sub, p.sub)` 表示角色继承匹配

### 2. 策略配置

- `p, admin, data1, read`：admin 角色可以读取 data1
- `p, admin, data1, write`：admin 角色可以写入 data1
- `g, alice, admin`：alice 继承 admin 角色
- `g, bob, user`：bob 继承 user 角色

### 3. 代码解析

- **创建执行器**：加载模型和策略文件
- **权限检查**：使用 `Enforce()` 方法检查权限
- **角色管理**：使用 `GetRolesForUser()` 和 `GetPermissionsForUser()` 管理角色
- **动态添加策略**：使用 `AddPolicy()` 动态添加策略

## 📦 步骤 8：尝试其他示例

### ABAC 属性匹配示例

创建 `resources/abac_model.conf` 文件：

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == r.obj.Owner
```

创建 `main_abac.go` 文件：

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

    log.InfoMsg("=== ABAC 属性匹配示例 ===")
    check(log, e, "alice", data1, "read")  // 允许（alice 是 Owner）
    check(log, e, "bob", data1, "read")    // 拒绝（bob 不是 Owner）
    check(log, e, "bob", data2, "write")   // 允许（bob 是 Owner）
}

func check(log logger.ILogger, e *enforcer.Enforcer, sub, obj, act interface{}) {
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

运行：

```bash
go run main_abac.go
```

### 多租户 RBAC 示例

创建 `resources/rbac_with_domains_model.conf` 文件：

```ini
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

创建 `resources/rbac_with_domains_policy.csv` 文件：

```csv
p, admin, tenant1, data1, read
p, admin, tenant1, data1, write
p, admin, tenant2, data2, read
p, viewer, tenant2, data2, read
g, alice, admin, tenant1
g, alice, viewer, tenant2
g, bob, viewer, tenant1
```

创建 `main_multitenant.go` 文件：

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

    log.InfoMsg("=== 多租户 RBAC 示例 ===")
    
    // alice 在 tenant1 中是 admin
    check(log, e, "alice", "tenant1", "data1", "read")   // 允许
    check(log, e, "alice", "tenant1", "data1", "write")  // 允许

    // alice 在 tenant2 中是 viewer
    check(log, e, "alice", "tenant2", "data2", "read")   // 允许
    check(log, e, "alice", "tenant2", "data2", "write")  // 拒绝

    // bob 只在 tenant1 中是 viewer
    check(log, e, "bob", "tenant1", "data1", "read")     // 允许
    check(log, e, "bob", "tenant2", "data2", "read")     // 拒绝

    // 多租户角色管理
    log.InfoMsg("=== 多租户角色管理示例 ===")
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

运行：

```bash
go run main_multitenant.go
```

## 📦 步骤 9：深入学习

1. **基础概念**：阅读 [模型配置指南](model-config.md) 了解模型配置语法
2. **策略管理**：阅读 [策略管理指南](policy-management.md) 学习如何管理策略
3. **角色管理**：阅读 [角色管理指南](role-management.md) 深入理解角色继承
4. **多租户**：阅读 [多租户指南](multitenancy.md) 掌握多租户隔离方案
5. **高级特性**：阅读 [高级特性指南](advanced-features.md) 了解企业级功能

## ❓ 常见问题

### Q: 运行时出现 "model file not found" 错误怎么办？

A: 确保模型文件路径正确，相对于当前工作目录

### Q: 权限检查总是返回 false 怎么办？

A: 检查模型配置和策略文件是否正确，特别是 matcher 表达式和策略规则

### Q: 如何添加自定义存储后端？

A: 实现 `Adapter` 接口，参考 [适配器使用指南](adapters.md)

### Q: 如何实现分布式策略同步？

A: 使用 Redis、Kafka 或 NATS 适配器，参考 [高级特性指南](advanced-features.md)

## 🚀 下一步

- 查看 [examples](/examples/) 目录中的完整示例
- 阅读 [API 文档](/docs/api.md) 了解详细 API
- 探索 [实时风控与反黑产](risk-control.md) 了解风控功能