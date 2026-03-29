# go-casbin 企业级权限管理系统

## 🎯 项目简介

go-casbin 是一个企业级的权限管理系统，基于 Go 语言开发，深度集成 [go-toolbox](https://github.com/kamalyes/go-toolbox) 和 [go-logger](https://github.com/kamalyes/go-logger)，提供全面、高效、可扩展的权限控制解决方案。

### 核心特性

- 📦 **全面性设计**：完整支持 ACL、RBAC、ABAC 等多种权限模型
- 🔧 **高度可扩展**：基于接口的适配器模式，支持自定义存储后端
- 🚀 **高性能**：利用 go-toolbox 的 syncx.Map、WorkerPool、对象池等优化并发性能
- 🛡️ **高可用**：集成 breaker 熔断器 + retry 重试机制，保障系统稳定性
- 🔍 **可观测性**：深度集成 go-logger，支持结构化日志、分布式追踪、Console风格
- 🔄 **热更新**：策略和配置支持运行时热加载，无需重启
- ⚡ **规则引擎**：基于 go-toolbox matcher 的高性能规则匹配引擎
- 🔐 **安全脱敏**：集成 desensitize 模块，日志自动脱敏

## 🏗️ 架构设计

### 架构层次图

```mermaid
graph TB
    subgraph "应用层"
        App[业务应用 API/Service]
        CLI[命令行工具 Admin]
    end

    subgraph "核心层"
        Enforcer[执行器 Enforcer<br/>权限检查入口<br/>breaker + retry]
        Matcher[匹配引擎 Matcher<br/>规则匹配与求值<br/>支持复杂表达式]
        Model[模型管理 Model<br/>模型加载与解析<br/>完整性验证]
        Policy[策略管理 Policy<br/>策略存储与更新<br/>缓存 + 监听器]
        Role[角色管理 Role<br/>角色层级与继承<br/>循环检测]
    end

    subgraph "存储层"
        Adapter[适配器接口 Adapter]
        Memory[内存存储<br/>并发安全 Map]
        File[文件存储<br/>CSV/JSON 格式]
        DB[数据库存储<br/>MySQL/PostgreSQL]
        Redis[Redis缓存<br/>分布式同步]
    end

    subgraph "工具与监控层"
        Toolbox[go-toolbox<br/>并发/错误/重试/ID生成]
        Logger[go-logger<br/>结构化日志/分布式追踪]
        Metrics[指标收集<br/>enforce_total/success]
        Health[健康检查<br/>存储连接状态]
    end

    App --> Enforcer
    CLI --> Enforcer
    Enforcer --> Matcher
    Enforcer --> Model
    Enforcer --> Policy
    Enforcer --> Role
    Policy --> Adapter
    Adapter --> Memory
    Adapter --> File
    Adapter --> DB
    Adapter --> Redis
    Enforcer --> Toolbox
    Enforcer --> Logger
    Enforcer --> Metrics
    Enforcer --> Health

    classDef appStyle fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef coreStyle fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef storageStyle fill:#e0f2f1,stroke:#00796b,stroke-width:2px
    classDef toolStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px

    class App,CLI appStyle
    class Enforcer,Matcher,Model,Policy,Role coreStyle
    class Adapter,Memory,File,DB,Redis storageStyle
    class Toolbox,Logger,Metrics,Health toolStyle
```

### 核心组件

- **执行器 (Enforcer)**：系统核心，负责权限检查的统一入口，集成熔断器和重试机制
- **匹配引擎 (Matcher)**：基于 go-toolbox/matcher 的高性能规则匹配引擎，支持复杂表达式解析
- **模型管理 (Model)**：处理权限模型的加载、验证和解析，支持多种权限模型
- **策略管理 (Policy)**：管理权限策略的存储、加载和更新，支持多种存储后端
- **角色管理 (Role)**：处理角色层级关系，支持角色继承和多租户隔离

### 扩展能力

- **适配器系统**：基于接口的适配器模式，支持文件、内存、数据库等多种存储后端
- **监控体系**：集成指标收集和健康检查，提供系统运行状态的可视化
- **企业级特性**：熔断、重试、分布式追踪、结构化日志等企业级功能
- **多租户支持**：基于域的多租户隔离方案，支持复杂的权限隔离需求

## 🚀 快速开始

### 安装

```bash
go get github.com/kamalyes/go-casbin
```

### 基础示例 - RBAC

```go
package main

import (
    "github.com/kamalyes/go-casbin/enforcer"
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

    // 权限检查
    ok, err := e.Enforce("alice", "data1", "read")
    log.InfoKV("权限检查结果", "sub", "alice", "obj", "data1", "act", "read", "ok", ok)
}
```

### 详细使用指南

更多详细的使用示例和指南，请参考 `docs/` 目录：

- [快速开始](docs/quickstart.md) - 一步一步教你使用 go-casbin
- [入门指南](docs/getting-started.md) - 从安装到基本使用的完整指南
- [模型配置指南](docs/model-config.md) - 详细的模型配置语法和示例
- [策略管理指南](docs/policy-management.md) - 策略的加载、保存、添加、删除和更新
- [角色管理指南](docs/role-management.md) - 角色的创建、继承、查询和管理
- [多租户指南](docs/multitenancy.md) - 多租户隔离方案和实现方法
- [适配器使用指南](docs/adapters.md) - 各种存储适配器的使用方法
- [高级特性指南](docs/advanced-features.md) - 熔断、重试、分布式追踪等企业级功能
- [实时风控与反黑产](docs/risk-control.md) - 实时风险评估和反黑产操作

## 📂 可运行示例

所有示例代码位于 `examples/` 目录，可直接运行验证效果：

| 示例 | 说明 | 运行命令 |
|------|------|----------|
| [rbac_basic](examples/rbac_basic/main.go) | RBAC 基本使用：角色继承 + 权限检查 | `go run examples/rbac_basic/main.go` |
| [abac_attribute](examples/abac_attribute/main.go) | ABAC 属性匹配：基于资源 Owner 字段判断 | `go run examples/abac_attribute/main.go` |
| [abac_rule](examples/abac_rule/main.go) | ABAC 规则策略：eval() 动态求值 + 独立 CSV | `go run examples/abac_rule/main.go` |
| [acl_basic](examples/acl_basic/main.go) | ACL 基本使用：无角色的直接权限控制 | `go run examples/acl_basic/main.go` |
| [rbac_domains](examples/rbac_domains/main.go) | 多租户 RBAC：域隔离 + 角色管理 API | `go run examples/rbac_domains/main.go` |
| [enterprise_multitenant](examples/enterprise_multitenant/main.go) | 企业级多租户：options 组合 + 熔断 + 重试 | `go run examples/enterprise_multitenant/main.go` |
| [enterprise_full](examples/enterprise_full/main.go) | 完整企业级：ORM + Redis + 分布式同步（需外部服务） | `go run -tags enterprise examples/enterprise_full/main.go` |

> **注意**：`enterprise_full` 示例需要 MySQL、Redis 等外部服务，使用 `//go:build enterprise` 构建标签隔离，需加 `-tags enterprise` 才会编译。

## 📚 详细文档

更详细的使用指南和技术文档位于 `docs/` 目录：

| 文档 | 说明 | 路径 |
|------|------|------|
| [快速开始](docs/quickstart.md) | 一步一步教你使用 go-casbin | `docs/quickstart.md` |
| [入门指南](docs/getting-started.md) | 从安装到基本使用的完整指南 | `docs/getting-started.md` |
| [模型配置指南](docs/model-config.md) | 详细的模型配置语法和示例 | `docs/model-config.md` |
| [策略管理指南](docs/policy-management.md) | 策略的加载、保存、添加、删除和更新 | `docs/policy-management.md` |
| [角色管理指南](docs/role-management.md) | 角色的创建、继承、查询和管理 | `docs/role-management.md` |
| [多租户指南](docs/multitenancy.md) | 多租户隔离方案和实现方法 | `docs/multitenancy.md` |
| [适配器使用指南](docs/adapters.md) | 各种存储适配器的使用方法 | `docs/adapters.md` |
| [高级特性指南](docs/advanced-features.md) | 熔断、重试、分布式追踪等企业级功能 | `docs/advanced-features.md` |
| [实时风控与反黑产](docs/risk-control.md) | 实时风险评估和反黑产操作 | `docs/risk-control.md` |

## 🎯 学习路径

1. **入门阶段**：阅读 [快速开始](docs/quickstart.md) 和 [入门指南](docs/getting-started.md)，掌握基本使用方法
2. **进阶阶段**：学习 [模型配置指南](docs/model-config.md) 和 [策略管理指南](docs/policy-management.md)，了解核心概念
3. **高级阶段**：探索 [多租户指南](docs/multitenancy.md)、[适配器使用指南](docs/adapters.md) 和 [高级特性指南](docs/advanced-features.md)，掌握企业级功能
4. **专家阶段**：研究 [实时风控与反黑产](docs/risk-control.md)，实现完整的权限和风控体系

## 📊 监控与日志

### 结构化日志输出

```
ℹ️ [INFO] 2026-03-29 23:59:00 Enforce result {sub: alice, obj: data1, act: read, ok: true}
ℹ️ [INFO] 2026-03-29 23:59:00 [trace_id=abc123] Policy check completed {duration: 0.15ms, result: allow}
❌ [ERROR] 2026-03-29 23:59:00 Enforce failed {sub: bob, obj: data2, act: write, error: forbidden}
```

### 监控指标

| 指标 | 说明 |
|------|------|
| `enforce_total` | 权限检查总次数 |
| `enforce_success` | 权限检查成功次数 |
| `enforce_failure` | 权限检查失败次数 |
| `enforce_latency` | 权限检查延迟 |
| `policy_updates` | 策略更新次数 |
| `cache_hits` | 缓存命中次数 |
| `cache_misses` | 缓存未命中次数 |
| `breaker_state` | 熔断器状态 |

## 🤝 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件