# 模型配置指南

## 🎯 目标

本指南详细介绍 go-casbin 的模型配置语法，帮助你理解并正确配置权限模型

## 📝 模型结构

Casbin 的模型基于 PERM 元模型（Policy Effect Request Matcher），由 5 个核心段组成：

1. **r** - Request Definition（请求定义）
2. **p** - Policy Definition（策略定义）
3. **g** - Role Definition（角色定义）
4. **e** - Policy Effect（策略效果）
5. **m** - Matchers（匹配器）

## 🔧 各段详细说明

### 1. r - Request Definition（请求定义）

定义访问请求的参数结构，即 `Enforce()` 方法接收的参数

```ini
[request_definition]
r = sub, obj, act          # 基本三段式
r = sub, obj, act, eft     # 带效果的四段式
r2 = sub, obj, act         # 多请求定义（用于复合场景）
```

| 参数 | 说明 | 示例 |
|------|------|------|
| `sub` | 主体（Subject），请求的发起者 | 用户名、角色名 |
| `obj` | 客体（Object），被访问的资源 | 数据、API、文件 |
| `act` | 操作（Action），对资源的访问方式 | read、write、delete |
| `eft` | 效果（Effect），可选，默认为空 | allow、deny |

### 2. p - Policy Definition（策略定义）

定义策略规则的参数结构，即 CSV 文件中每行策略的字段含义

```ini
[policy_definition]
p = sub, obj, act          # 基本策略：谁 对 什么资源 做什么操作
p = sub, obj, act, eft     # 带效果的策略：可指定 allow 或 deny
p2 = sub, obj, act         # 多策略定义
```

对应 CSV 策略示例：

```csv
p, alice, data1, read      # sub=alice, obj=data1, act=read
p, bob, data2, write       # sub=bob, obj=data2, act=write
p, eve, data3, read, deny  # 显式拒绝
```

> **注意**：策略行支持包含括号和逗号的复杂表达式，如 `p, r.sub in ("alice", "bob"), data4, read`，解析器会智能处理括号内的逗号

### 3. g - Role Definition（角色定义）

定义角色继承关系，支持多层级角色和域（domain）隔离

```ini
[role_definition]
g = _, _                   # 基本角色：用户 -> 角色
g2 = _, _, _               # 带域的角色：用户 -> 角色 -> 域（多租户场景）
g = _, _                   # 支持多层继承：admin -> super_admin -> root
```

对应 CSV 策略示例：

```csv
g, alice, admin            # alice 继承 admin 角色
g, bob, user               # bob 继承 user 角色
g, admin, super_admin      # admin 继承 super_admin（多层继承）
g2, alice, admin, tenant1  # alice 在 tenant1 域中是 admin
```

### 4. e - Policy Effect（策略效果）

定义当多条策略同时匹配时的组合效果，决定最终是允许还是拒绝

| 表达式 | 含义 | 适用场景 |
|--------|------|----------|
| `some(where (p.eft == allow))` | 任一策略允许则允许 | 默认允许模式（白名单） |
| `!some(where (p.eft == deny))` | 没有策略拒绝则允许 | 默认拒绝模式（黑名单） |
| `some(where (p.eft == allow)) && !some(where (p.eft == deny))` | 有允许且无拒绝才允许 | 严格模式（需同时满足） |

```ini
[policy_effect]
e = some(where (p.eft == allow))                              # 标准白名单
e = !some(where (p.eft == deny))                              # 标准黑名单
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))  # 严格模式
```

### 5. m - Matchers（匹配器）

定义请求与策略之间的匹配逻辑，支持逻辑运算符和内置函数

| 运算符/函数 | 说明 | 示例 |
|-------------|------|------|
| `&&` | 逻辑与 | `r.sub == p.sub && r.obj == p.obj` |
| `\|\|` | 逻辑或 | `r.act == "read" \|\| r.act == "write"` |
| `==` | 等于 | `r.sub == p.sub` |
| `!=` | 不等于 | `r.sub != "root"` |
| `in` | 包含 | `r.sub in ("alice", "bob")` |
| `g(r.sub, p.sub)` | 角色继承匹配 | alice 是否继承自 admin |
| `eval()` | ABAC 属性求值 | `eval(p.sub)` 动态解析属性 |
| `r.obj.Owner` | 对象属性访问 | ABAC 中访问资源的 Owner 字段 |

```ini
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act       # ACL：精确匹配
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act      # RBAC：角色匹配
m = r.sub == r.obj.Owner                                       # ABAC：属性匹配
m = g(r.sub, p.sub) && r.obj == p.obj && eval(p.act)          # 混合模式
```

## 🎨 常见模型配置

### 1. ACL 模型

最简单的权限模型，直接定义用户对资源的操作权限

```ini
# resources/acl_model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

### 2. RBAC 模型

基于角色的访问控制，通过角色继承实现权限管理

```ini
# resources/rbac_model.conf
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

### 3. ABAC 属性匹配模型

基于资源属性的访问控制，不需要策略文件

```ini
# resources/abac_model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == r.obj.Owner
```

### 4. ABAC 规则策略模型

将条件表达式写入策略文件，通过 `eval()` 动态求值

```ini
# resources/abac_rule_model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_rule, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act
```

### 5. 多租户 RBAC 模型

支持域隔离的 RBAC 模型，适用于多租户场景

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

### 6. 优先级策略模型

当多条策略冲突时，按优先级决定最终结果

```ini
# resources/priority_model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = priority, sub, obj, act, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

### 7. 拒绝覆盖模型

在白名单基础上增加显式拒绝规则，拒绝优先于允许

```ini
# resources/deny_override_model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

## 🔍 模型解析流程

1. **加载模型**：从文件或字符串加载模型配置
2. **解析各段**：解析 r/p/g/e/m 各段的定义
3. **构建 Token**：为每个段的参数构建带前缀的 Token（如 `r.sub`、`p.sub`）
4. **验证完整性**：检查模型配置的完整性和正确性
5. **生成断言**：为每个段生成对应的断言对象

## 📝 最佳实践

### 1. 命名规范

- **段名**：使用小写字母（r/p/g/e/m）
- **参数名**：使用小写字母和下划线（sub/obj/act）
- **策略文件**：使用 `.csv` 扩展名，保持格式清晰
- **模型文件**：使用 `.conf` 扩展名，按照标准 INI 格式

### 2. 性能优化

- **减少策略数量**：合理使用角色继承，避免重复策略
- **优化匹配器**：使用简单的匹配表达式，避免复杂逻辑
- **使用缓存**：对于频繁访问的权限检查，考虑使用缓存

### 3. 安全性

- **最小权限原则**：只授予必要的权限
- **定期审计**：定期检查和清理策略
- **避免硬编码**：使用配置文件管理策略，避免在代码中硬编码

## ❓ 常见问题

### Q: 如何定义多个角色继承关系？

A: 使用多个角色定义段：

```ini
[role_definition]
g = _, _       # 用户 -> 角色
g2 = _, _, _   # 角色 -> 角色（多层继承）
g3 = _, _, _   # 带域的角色
```

### Q: 如何实现复杂的条件判断？

A: 使用 `eval()` 函数和 `in` 运算符：

```csv
p, r.sub == "admin" || r.sub in ("alice", "bob"), data1, read
```

### Q: 如何处理带参数的角色？

A: 使用 RBAC with Domains 模型，将参数作为域字段：

```csv
g, alice, editor, project1
g, alice, viewer, project2
```

### Q: 如何实现动态权限？

A: 使用 ABAC 规则策略模式，通过 `eval()` 动态求值：

```csv
p, r.sub.Role == "admin" && r.obj.Owner == r.sub, data1, write
```

## 🔄 代码中使用模型配置

除了从 `.conf` 文件加载模型外，go-casbin 还支持在代码中直接通过内联字符串创建模型，这在单元测试和动态场景中非常实用。

### 从字符串创建模型

使用 `model.NewModelFromText()` 方法，直接传入 INI 格式的模型配置字符串：

```go
import (
    "github.com/kamalyes/go-casbin/model"
    "github.com/kamalyes/go-logger"
)

m, err := model.NewModelFromText(`
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
`, logger.NewLogger())
```

### 模型配置字符串格式说明

模型配置字符串遵循标准 INI 格式，由 `[段名]` 标记各段，等号左侧为段标识符，右侧为参数列表：

```
[段名]
标识符 = 参数1, 参数2, 参数3, ...
```

| 段名 | 标识符 | 含义 | 示例 |
|------|--------|------|------|
| `[request_definition]` | `r` | 请求参数定义 | `r = sub, obj, act` |
| `[policy_definition]` | `p` | 策略参数定义 | `p = sub, obj, act` |
| `[role_definition]` | `g` | 角色继承定义 | `g = _, _`（两段式）或 `g = _, _, _`（带域） |
| `[policy_effect]` | `e` | 策略效果组合 | `e = some(where (p.eft == allow))` |
| `[matchers]` | `m` | 匹配器表达式 | `m = r.sub == p.sub && r.obj == p.obj` |

### 各段参数占位符

- **`_`**（下划线）：在 `role_definition` 中表示占位符，`g = _, _` 表示两参数（用户、角色），`g = _, _, _` 表示三参数（用户、角色、域）
- **`sub` / `obj` / `act`**：分别代表主体、客体、操作，是最常用的三段式参数
- **`eft`**：效果字段，取值为 `allow` 或 `deny`，用于策略效果组合

### 常见模型配置字符串模板

#### ACL 模型

```go
m, _ := model.NewModelFromText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
```

#### RBAC 模型

```go
m, _ := model.NewModelFromText(`
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
`, logger.NewLogger())
```

#### 多租户 RBAC 模型

```go
m, _ := model.NewModelFromText(`
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
`, logger.NewLogger())
```

### 在测试中使用

在单元测试中，使用 `NewModelFromText` 可以避免依赖外部 `.conf` 文件，使测试自包含且更易维护：

```go
func TestPolicy_CRUD(t *testing.T) {
    m, err := model.NewModelFromText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`, logger.NewLogger())
    require.NoError(t, err)

    p := policy.NewPolicy(m, policy.NewMemoryAdapter(), logger.NewLogger())

    // 测试策略 CRUD...
    err = p.AddPolicy("", "p", []string{"alice", "data1", "read"})
    require.NoError(t, err)
    assert.True(t, p.HasPolicy("p", []string{"alice", "data1", "read"}))
}
```

### 从文件加载 vs 从字符串创建

| 特性 | `NewModelFromFile` / `WithModelPath` | `NewModelFromText` |
|------|--------------------------------------|---------------------|
| 配置来源 | `.conf` 文件 | 内联字符串 |
| 适用场景 | 生产环境、配置需要独立管理 | 单元测试、动态配置、原型验证 |
| 可维护性 | 高，配置与代码分离 | 低，配置嵌入代码中 |
| 热更新 | 支持（文件监听） | 不支持 |
| 依赖 | 需要文件系统 | 无外部依赖 |

> **提示**：生产环境推荐使用 `.conf` 文件方式，便于配置管理和热更新；测试和动态场景推荐使用 `NewModelFromText`，避免文件依赖。

## 🚀 下一步

- 查看 [策略管理指南](policy-management.md) 学习如何管理策略
- 阅读 [角色管理指南](role-management.md) 深入理解角色继承
- 探索 [多租户指南](multitenancy.md) 掌握多租户隔离方案