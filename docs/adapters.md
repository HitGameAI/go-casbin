# 适配器使用指南

## 🎯 目标

本指南详细介绍 go-casbin 的各种存储适配器，帮助你选择和使用适合的存储后端

## 📝 适配器基础

### 什么是适配器？

适配器是 go-casbin 与存储后端之间的桥梁，负责策略的加载、保存和管理

### 适配器接口

所有适配器都实现了 `Adapter` 接口：

```go
type Adapter interface {
    // LoadPolicy 从存储加载策略
    LoadPolicy(model model.Model) error
    // SavePolicy 保存策略到存储
    SavePolicy(model model.Model) error
    // AddPolicy 添加单条策略
    AddPolicy(line string) error
    // RemovePolicy 删除单条策略
    RemovePolicy(line string) error
    // UpdatePolicy 更新策略
    UpdatePolicy(oldLine, newLine string) error
    // AddPolicies 批量添加策略
    AddPolicies(lines []string) error
    // RemovePolicies 批量删除策略
    RemovePolicies(lines []string) error
    // UpdatePolicies 批量更新策略
    UpdatePolicies(oldLines, newLines []string) error
}
```

## 🔧 内置适配器

### 1. 文件适配器（FileAdapter）

最基础的适配器，将策略存储在 CSV 文件中

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
)

// 创建执行器时指定策略文件路径
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
)

// 或手动创建文件适配器
fa := policy.NewFileAdapter("resources/rbac_policy.csv")
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithAdapter(fa),
)
```

#### 特点

- **优点**：简单易用，适合小型应用
- **缺点**：不适合高并发场景，不支持分布式
- **适用场景**：本地开发、测试环境、小型应用

### 2. 内存适配器（MemoryAdapter）

将策略存储在内存中，适合临时策略或测试

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    "github.com/kamalyes/go-casbin/policy"
)

// 创建内存适配器
ma := policy.NewMemoryAdapter()

// 添加策略
ma.AddPolicy("p, alice, data1, read")
ma.AddPolicy("p, bob, data2, write")
ma.AddPolicy("g, alice, admin")

// 创建执行器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithAdapter(ma),
)
```

#### 特点

- **优点**：速度快，适合临时策略
- **缺点**：重启后策略丢失
- **适用场景**：临时策略、测试环境、内存计算

## 🎨 外部适配器

### 1. ORM 适配器（go-casbin-gorm-adapter）

基于 go-sqlbuilder 的 ORM 适配器，支持 MySQL、PostgreSQL、SQLite 等关系型数据库

#### 安装

```bash
go get github.com/kamalyes/go-casbin-gorm-adapter
```

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    gormadapter "github.com/kamalyes/go-casbin-gorm-adapter"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// 连接数据库
db, err := gorm.Open(mysql.Open("user:pass@tcp(127.0.0.1:3306)/casbin?charset=utf8mb4&parseTime=True"), &gorm.Config{})
if err != nil {
    panic(err)
}

// 创建 ORM 适配器
ormAdapter, err := gormadapter.NewAdapterByDB(db,
    gormadapter.WithTableName("casbin_rule"),  // 自定义表名
    gormadapter.WithLogger(log),              // 自定义日志
)
if err != nil {
    panic(err)
}

// 创建执行器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithAdapter(ormAdapter),
    enforcer.WithAutoSave(true),
)
```

#### 特点

- **优点**：持久化存储，支持事务，适合生产环境
- **缺点**：配置稍复杂
- **适用场景**：生产环境、需要持久化的应用

### 2. Redis 适配器（go-casbin-redis-adapter）

基于 go-cachex 的 Redis 适配器，支持缓存和 Pub/Sub 分布式同步

#### 安装

```bash
go get github.com/kamalyes/go-casbin-redis-adapter
```

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    redisadapter "github.com/kamalyes/go-casbin-redis-adapter"
    "github.com/redis/go-redis/v9"
)

// 连接 Redis
rdb := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "", // 无密码
    DB:       0,  // 默认 DB
})

// 创建 Redis 适配器
redisAdapter, err := redisadapter.NewRedisAdapter(rdb,
    redisadapter.WithKeyPrefix("casbin:"),  // 自定义 Key 前缀
)
if err != nil {
    panic(err)
}

// 创建执行器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithAdapter(redisAdapter),
    enforcer.WithAutoSave(true),
)
```

#### 特点

- **优点**：高性能，支持分布式，适合高并发
- **缺点**：依赖 Redis 服务
- **适用场景**：高并发场景、分布式部署

### 3. Kafka 适配器（go-casbin-kafka-adapter）

基于 Kafka 的分布式策略同步适配器，适合大规模部署

#### 安装

```bash
go get github.com/kamalyes/go-casbin-kafka-adapter
```

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    kafkaadapter "github.com/kamalyes/go-casbin-kafka-adapter"
)

// 创建 Kafka 通知器
notifier, err := kafkaadapter.NewKafkaNotifier(
    &kafkaadapter.KafkaConfig{
        Brokers: []string{"kafka-1:9092", "kafka-2:9092"},
        GroupID: "casbin-policy-node-1",
    },
    policy.WithChannel("casbin-policy-changes"),
)
if err != nil {
    panic(err)
}

// 创建执行器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
    enforcer.WithNotifier(notifier),
)
```

#### 特点

- **优点**：高可靠性，支持大规模部署，跨数据中心
- **缺点**：配置复杂，依赖 Kafka 集群
- **适用场景**：大规模分布式部署、跨数据中心

### 4. NATS 适配器（go-casbin-nats-adapter）

基于 NATS 的低延迟策略同步适配器，适合对延迟敏感的场景

#### 安装

```bash
go get github.com/kamalyes/go-casbin-nats-adapter
```

#### 配置与使用

```go
import (
    "github.com/kamalyes/go-casbin/enforcer"
    natsadapter "github.com/kamalyes/go-casbin-nats-adapter"
)

// 创建 NATS 通知器
notifier, err := natsadapter.NewNATSNotifier(
    &natsadapter.NATSConfig{
        URL:       "nats://localhost:4222",
        JetStream: true,
    },
    policy.WithChannel("casbin.policy.changes"),
)
if err != nil {
    panic(err)
}

// 创建执行器
e, err := enforcer.NewEnforcer(
    enforcer.WithModelPath("resources/rbac_model.conf"),
    enforcer.WithPolicyPath("resources/rbac_policy.csv"),
    enforcer.WithNotifier(notifier),
)
```

#### 特点

- **优点**：低延迟，轻量级，支持 JetStream 持久化
- **缺点**：依赖 NATS 服务
- **适用场景**：低延迟场景、实时应用

## 🔧 自定义适配器

如果你需要使用其他存储后端，可以实现 `Adapter` 接口：

```go
import (
    "github.com/kamalyes/go-casbin/model"
    "github.com/kamalyes/go-casbin/policy"
)

// MyAdapter 自定义适配器
type MyAdapter struct {
    // 存储连接等
}

// LoadPolicy 从存储加载策略
func (a *MyAdapter) LoadPolicy(m model.Model) error {
    // 实现加载逻辑
    return nil
}

// SavePolicy 保存策略到存储
func (a *MyAdapter) SavePolicy(m model.Model) error {
    // 实现保存逻辑
    return nil
}

// AddPolicy 添加单条策略
func (a *MyAdapter) AddPolicy(line string) error {
    // 实现添加逻辑
    return nil
}

// RemovePolicy 删除单条策略
func (a *MyAdapter) RemovePolicy(line string) error {
    // 实现删除逻辑
    return nil
}

// UpdatePolicy 更新策略
func (a *MyAdapter) UpdatePolicy(oldLine, newLine string) error {
    // 实现更新逻辑
    return nil
}

// AddPolicies 批量添加策略
func (a *MyAdapter) AddPolicies(lines []string) error {
    // 实现批量添加逻辑
    return nil
}

// RemovePolicies 批量删除策略
func (a *MyAdapter) RemovePolicies(lines []string) error {
    // 实现批量删除逻辑
    return nil
}

// UpdatePolicies 批量更新策略
func (a *MyAdapter) UpdatePolicies(oldLines, newLines []string) error {
    // 实现批量更新逻辑
    return nil
}

// NewMyAdapter 创建自定义适配器
func NewMyAdapter() *MyAdapter {
    return &MyAdapter{}
}
```

## 🔍 适配器选择指南

| 适配器 | 适用场景 | 延迟 | 持久化 | 复杂度 | 分布式 |
|--------|----------|------|--------|--------|--------|
| 文件适配器 | 本地开发、测试 | 低 | ✅ | 低 | ❌ |
| 内存适配器 | 临时策略、测试 | 极低 | ❌ | 极低 | ❌ |
| ORM 适配器 | 生产环境、持久化 | 中 | ✅ | 中 | ❌ |
| Redis 适配器 | 高并发、分布式 | 低 | ✅ | 中 | ✅ |
| Kafka 适配器 | 大规模、跨数据中心 | 中 | ✅ | 高 | ✅ |
| NATS 适配器 | 低延迟、实时 | 极低 | ✅ | 中 | ✅ |

## 📝 最佳实践

### 1. 生产环境选择

- **小规模应用**：文件适配器或 ORM 适配器
- **中规模应用**：Redis 适配器
- **大规模应用**：Kafka 适配器
- **低延迟应用**：NATS 适配器

### 2. 性能优化

- **批量操作**：使用批量 API 减少存储操作次数
- **缓存利用**：依赖 Redis 适配器的缓存功能
- **连接池**：为 ORM 适配器配置合理的连接池
- **异步操作**：将非实时操作异步处理

### 3. 安全性

- **访问控制**：限制适配器的存储访问权限
- **加密存储**：对敏感策略进行加密存储
- **审计日志**：记录策略的变更历史
- **备份恢复**：定期备份策略数据

### 4. 监控与维护

- **健康检查**：监控适配器的连接状态
- **性能监控**：监控存储操作的延迟和吞吐量
- **错误处理**：实现优雅的错误处理和重试机制
- **版本管理**：管理存储模式的版本变更

## ❓ 常见问题

### Q: 如何实现适配器的高可用？

A: 
- **ORM 适配器**：使用数据库集群
- **Redis 适配器**：使用 Redis 哨兵或集群
- **Kafka 适配器**：使用 Kafka 集群
- **NATS 适配器**：使用 NATS 集群

### Q: 如何处理适配器的连接失败？

A: 
- 实现连接重试机制
- 使用断路器模式
- 配置合理的超时时间
- 实现优雅的降级策略

### Q: 如何迁移策略数据？

A: 
- 从旧适配器加载策略
- 保存到新适配器
- 验证数据完整性
- 切换到新适配器

### Q: 如何实现适配器的动态切换？

A: 
- 实现适配器工厂模式
- 支持运行时切换适配器
- 确保切换过程中的数据一致性

## 🚀 下一步

- 查看 [高级特性指南](advanced-features.md) 掌握企业级功能
- 阅读 [实时风控与反黑产](risk-control.md) 了解风控功能
- 探索 [示例代码](/examples/) 学习实际使用场景