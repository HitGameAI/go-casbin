# 高级特性指南

## 🎯 目标

本指南详细介绍 go-casbin 的高级特性，帮助你掌握企业级功能的使用方法

## 📝 高级特性概览

go-casbin 集成了 go-toolbox 的多种企业级特性：

- **断路器**：防止系统雪崩
- **重试机制**：提高系统可靠性
- **分布式追踪**：全链路监控
- **结构化日志**：统一日志格式
- **热更新**：策略和配置实时更新
- **并发优化**：提高系统性能

## 🔧 断路器（Circuit Breaker）

### 什么是断路器？

断路器是一种容错模式，当服务调用失败率达到阈值时，会自动熔断，避免系统雪崩

### 配置与使用

```go
import (
    "time"

    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
    "github.com/kamalyes/go-toolbox/pkg/breaker"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 创建执行器并配置断路器
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
        enforcer.WithBreaker("casbin", breaker.Config{
            MaxFailures:  5,             // 最大失败次数
            ResetTimeout: 30 * time.Second, // 重置超时时间
            Interval:     10 * time.Second, // 统计间隔
        }),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 权限检查（会经过断路器）
    ok, err := e.Enforce("alice", "data1", "read")
}
```

### 断路器状态

- **Closed**：正常状态，允许请求通过
- **Open**：熔断状态，拒绝所有请求
- **Half-Open**：半开状态，允许部分请求通过以测试服务是否恢复

### 最佳实践

- **合理配置阈值**：根据实际服务质量设置失败率阈值
- **监控状态**：定期监控断路器状态
- **优雅降级**：当断路器打开时，提供降级策略

## 🔧 重试机制（Retry）

### 什么是重试机制？

重试机制是一种容错模式，当操作失败时自动重试，提高系统可靠性

### 配置与使用

```go
import (
    "time"

    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
    "github.com/kamalyes/go-toolbox/pkg/retry"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 创建执行器并配置重试机制
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
        enforcer.WithRetry(
            retry.NewRetry().
                SetAttemptCount(3).          // 最大尝试次数
                SetInterval(100 * time.Millisecond). // 初始间隔
                SetBackoffMultiplier(2.0),    // 退避乘数
                SetMaxInterval(1 * time.Second), // 最大间隔
        ),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 权限检查（失败时会自动重试）
    ok, err := e.Enforce("alice", "data1", "read")
}
```

### 重试策略

- **固定间隔**：每次重试间隔相同
- **指数退避**：每次重试间隔指数增长
- **随机退避**：在一定范围内随机调整重试间隔

### 最佳实践

- **合理配置重试次数**：避免过多重试导致系统过载
- **设置最大间隔**：防止重试间隔过长影响用户体验
- **选择合适的退避策略**：根据服务特性选择合适的重试策略

## 🔧 分布式追踪

### 什么是分布式追踪？

分布式追踪是一种监控技术，通过 trace ID 跟踪请求在分布式系统中的全链路流转

### 配置与使用

```go
import (
    "context"

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

    // 创建带 trace ID 的上下文
    ctx := context.Background()
    ctx = log.WithContextValue(ctx, "trace_id", "abc123")

    // 权限检查（会记录 trace ID）
    ok, err := e.EnforceWithContext(ctx, "alice", "data1", "read")
}
```

### 日志输出

```
ℹ️ [INFO] 2026-05-15 10:30:00 [trace_id=abc123] Enforce result {sub: alice, obj: data1, act: read, ok: true}
ℹ️ [INFO] 2026-05-15 10:30:00 [trace_id=abc123] Policy check completed {duration: 0.15ms, result: allow}
```

### 最佳实践

- **统一 trace ID**：在整个系统中使用统一的 trace ID
- **上下文传递**：通过 context 传递 trace ID
- **集成监控系统**：将追踪数据集成到监控系统

## 🔧 结构化日志

### 什么是结构化日志？

结构化日志是一种以键值对形式记录的日志，便于机器解析和分析

### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    // 创建结构化日志器
    log := logger.NewLogger().
        WithLevel(logger.INFO).
        WithShowCaller(true).
        WithShowTimestamp(true)

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
    log.InfoKV("Enforce result", "sub", "alice", "obj", "data1", "act", "read", "ok", ok)
}
```

### 日志级别

- **DEBUG**：详细调试信息
- **INFO**：一般信息
- **WARN**：警告信息
- **ERROR**：错误信息
- **FATAL**：致命错误，程序会退出

### 最佳实践

- **合理使用日志级别**：根据信息重要性选择合适的日志级别
- **统一日志格式**：在整个系统中使用统一的日志格式
- **避免敏感信息**：使用脱敏功能处理敏感信息
- **集成日志系统**：将日志集成到 ELK 等日志系统

## 🔧 热更新

### 什么是热更新？

热更新是指在不重启服务的情况下，实时更新策略和配置

### 策略热更新

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 创建执行器（自动启用文件监听器）
    e, err := enforcer.NewEnforcer(
        enforcer.WithModelPath("resources/rbac_model.conf"),
        enforcer.WithPolicyPath("resources/rbac_policy.csv"),
        enforcer.WithLogger(log),
    )
    if err != nil {
        log.Fatal("创建执行器失败: %v", err)
    }

    // 当策略文件变更时，会自动重载
    // 无需手动调用 LoadPolicy()
}
```

### 配置热更新

```go
import (
    "github.com/kamalyes/go-casbin/config"
    "github.com/kamalyes/go-logger"
)

func main() {
    log := logger.NewLogger().WithLevel(logger.INFO)

    // 加载配置并启用热更新
    cfg, err := config.LoadConfigWithWatcher("configs/config.yaml", log)
    if err != nil {
        log.Fatal("加载配置失败: %v", err)
    }

    // 配置变更时会自动更新
    // 可以通过 cfg.Get() 获取最新配置
}
```

### 最佳实践

- **监控文件变更**：确保文件监听器正常工作
- **平滑过渡**：在热更新时确保服务不中断
- **验证配置**：在加载新配置前进行验证
- **回滚机制**：当新配置有问题时能够回滚

## 🔧 并发优化

### 并发安全

go-casbin 使用 `syncx.Map` 实现并发安全的策略缓存：

```go
// 内部使用 syncx.Map 存储策略
// 支持并发读写，无需额外加锁
policies := e.GetPolicy()
```

### 工作池

使用 `WorkerPool` 处理批量权限检查：

```go
import (
    "github.com/kamalyes/go-toolbox/pkg/syncx"
)

func main() {
    // 创建工作池
    pool := syncx.NewWorkerPool(10) // 10 个工作协程

    // 提交任务
    for i := 0; i < 100; i++ {
        pool.Submit(func() {
            // 权限检查
            ok, _ := e.Enforce("alice", "data1", "read")
        })
    }

    // 等待所有任务完成
    pool.Wait()
}
```

### 对象池

使用对象池减少内存分配：

```go
import (
    "github.com/kamalyes/go-toolbox/pkg/syncx"
)

// 定义对象池
type EnforceRequest struct {
    Sub string
    Obj string
    Act string
}

var requestPool = syncx.NewObjectPool(func() interface{} {
    return &EnforceRequest{}
})

func main() {
    // 从对象池获取对象
    req := requestPool.Get().(*EnforceRequest)
    req.Sub = "alice"
    req.Obj = "data1"
    req.Act = "read"

    // 使用对象
    ok, _ := e.Enforce(req.Sub, req.Obj, req.Act)

    // 重置并归还对象
    req.Sub = ""
    req.Obj = ""
    req.Act = ""
    requestPool.Put(req)
}
```

### 最佳实践

- **合理配置并发度**：根据系统资源配置合适的并发度
- **避免锁竞争**：使用无锁数据结构
- **内存管理**：使用对象池减少内存分配
- **监控性能**：定期监控系统性能指标

## 🔧 错误处理

### 统一错误处理

go-casbin 使用 `errorx` 包实现统一的错误处理：

```go
import (
    "github.com/kamalyes/go-casbin/errors"
    "github.com/kamalyes/go-toolbox/pkg/errorx"
)

func main() {
    // 包装错误
    err := errorx.WrapError("权限检查失败", originalErr)
    
    // 检查错误类型
    if errors.IsPolicyAdapterFailedError(err) {
        // 处理适配器错误
    }

    // 获取错误堆栈
    stack := errorx.GetStack(err)
    log.Error("错误堆栈: %s", stack)
}
```

### 错误类型

- **PolicyAdapterFailedError**：适配器操作失败
- **PolicyAlreadyExistsError**：策略已存在
- **PolicyNotFoundError**：策略不存在
- **ModelLoadFailedError**：模型加载失败
- **EnforceFailedError**：权限检查失败

### 最佳实践

- **统一错误处理**：使用 errorx 包装所有错误
- **错误分类**：根据错误类型进行不同处理
- **错误日志**：记录详细的错误信息和堆栈
- **错误监控**：监控错误率和类型分布

## 🔍 性能优化

### 1. 策略缓存

- **启用缓存**：默认启用策略缓存
- **缓存失效**：策略变更时自动失效
- **缓存大小**：根据内存情况调整缓存大小

### 2. 批量操作

- **批量添加**：使用 AddPolicies 批量添加策略
- **批量删除**：使用 RemovePolicies 批量删除策略
- **批量更新**：使用 UpdatePolicies 批量更新策略

### 3. 索引优化

- **策略索引**：为常用查询建立索引
- **角色索引**：优化角色继承查询
- **域索引**：优化多租户查询

### 4. 编译优化

- **预编译匹配器**：提前编译 matcher 表达式
- **减少反射**：避免运行时反射
- **内联函数**：对热点函数进行内联

## 📝 最佳实践

### 1. 生产环境配置

- **断路器**：启用断路器保护系统
- **重试机制**：配置合理的重试策略
- **监控**：集成监控系统
- **日志**：使用结构化日志
- **热更新**：启用策略热更新

### 2. 性能调优

- **并发度**：根据系统资源调整并发度
- **缓存**：合理使用缓存
- **批量操作**：使用批量 API
- **索引**：优化数据库索引

### 3. 安全性

- **最小权限**：只授予必要的权限
- **审计**：定期审计策略
- **加密**：对敏感数据进行加密
- **访问控制**：限制管理接口的访问

### 4. 可维护性

- **文档**：完善文档
- **测试**：编写单元测试和集成测试
- **监控**：设置合理的监控告警
- **日志**：统一日志格式和级别

## ❓ 常见问题

### Q: 如何选择断路器和重试的配置？

A: 
- **断路器**：根据服务的容错能力设置 MaxFailures 和 ResetTimeout
- **重试**：根据操作的幂等性和服务响应时间设置重试次数和间隔

### Q: 如何处理分布式环境下的策略一致性？

A: 
- 使用 Redis Pub/Sub 或 Kafka 实现策略同步
- 配置合理的同步频率
- 实现最终一致性机制

### Q: 如何优化高并发场景下的性能？

A: 
- 使用 Redis 适配器
- 启用策略缓存
- 使用工作池处理批量请求
- 优化数据库索引

### Q: 如何实现权限检查的降级策略？

A: 
- 当断路器打开时，返回默认权限
- 实现本地缓存作为降级方案
- 提供备用的权限检查机制

## 🚀 下一步

- 查看 [实时风控与反黑产](risk-control.md) 了解风控功能
- 阅读 [示例代码](/examples/) 学习实际使用场景
- 探索 [API 文档](/docs/api.md) 了解详细 API