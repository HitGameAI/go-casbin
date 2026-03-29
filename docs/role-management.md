# 角色管理指南

## 🎯 目标

本指南详细介绍 go-casbin 的角色管理功能，帮助你掌握角色的创建、继承、查询和管理操作

## 📝 角色基础

### 角色定义

角色是权限的集合，通过角色继承可以实现权限的分层管理

### 角色继承关系

角色继承是 RBAC 模型的核心特性，支持多层级继承：

```
root
└── super_admin
    └── admin
        └── user
```

### 角色类型

1. **基本角色**：直接分配给用户的角色
2. **继承角色**：从其他角色继承权限的角色
3. **域角色**：在特定域（租户）中有效的角色

## 🔧 角色管理 API

### 1. 基本角色管理

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

// 删除用户的所有角色
err := e.DeleteRolesForUser("alice")

// 删除角色
err := e.DeleteRole("admin")

// 检查角色是否存在
exists := e.HasRole("admin")
```

### 2. 多层角色继承

```go
// 添加多层角色继承
err := e.AddRoleForUser("alice", "user")
err = e.AddRoleForUser("user", "admin")
err = e.AddRoleForUser("admin", "super_admin")

// 获取用户的所有角色（包括继承的）
roles := e.GetRolesForUser("alice") // 返回 ["user", "admin", "super_admin"]

// 检查间接角色继承关系
hasRole := e.HasRoleForUser("alice", "super_admin") // 返回 true
```

### 3. 多租户角色管理

```go
// 添加带域的角色继承
err := e.AddRoleForUserInDomain("alice", "admin", "tenant1")
err = e.AddRoleForUserInDomain("alice", "viewer", "tenant2")

// 获取用户在特定域中的角色
roles := e.GetRolesForUserInDomain("alice", "tenant1") // 返回 ["admin"]

// 删除带域的角色继承
err := e.DeleteRoleForUserInDomain("alice", "admin", "tenant1")

// 检查带域的角色继承关系
hasRole := e.HasRoleForUserInDomain("alice", "admin", "tenant1")

// 获取域中角色的用户
users := e.GetUsersForRoleInDomain("admin", "tenant1")
```

### 4. 角色权限管理

```go
// 获取角色的权限
perms := e.GetPermissionsForUser("admin")

// 获取带域的角色权限
perms := e.GetPermissionsForUserInDomain("admin", "tenant1")

// 为角色添加权限
err := e.AddPolicy("admin", "data1", "read")
err = e.AddPolicy("admin", "data1", "write")

// 从角色移除权限
err := e.RemovePolicy("admin", "data1", "write")
```

## 🎨 高级角色管理

### 1. 角色层级管理

```go
// 检查角色是否有子角色
hasChildren := e.HasChildRole("admin", "user")

// 获取角色的子角色
children := e.GetChildRoles("admin")

// 获取角色的父角色
parents := e.GetParentRoles("user")
```

### 2. 循环检测

go-casbin 自动检测角色继承循环：

```go
// 尝试创建循环继承（会失败）
err := e.AddRoleForUser("alice", "admin")
err = e.AddRoleForUser("admin", "super_admin")
err = e.AddRoleForUser("super_admin", "alice") // 会返回错误
```

### 3. 角色合并

```go
// 为用户添加多个角色
err := e.AddRoleForUser("alice", "admin")
err = e.AddRoleForUser("alice", "manager")

// 获取用户的所有角色
roles := e.GetRolesForUser("alice") // 返回 ["admin", "manager"]

// 用户会继承所有角色的权限
```

### 4. 角色模板

创建角色模板，批量应用到多个用户：

```go
// 定义角色模板
adminTemplate := []string{
    "admin", "data1", "read",
    "admin", "data1", "write",
    "admin", "data2", "read",
}

// 批量添加角色权限
err := e.AddPolicies(adminTemplate)

// 为用户分配角色
err := e.AddRoleForUser("alice", "admin")
err = e.AddRoleForUser("bob", "admin")
```

## 🔍 角色继承机制

### 1. 继承原理

角色继承通过 `g` 段定义，支持：

- **直接继承**：用户直接继承角色
- **间接继承**：角色继承其他角色
- **多层继承**：支持任意深度的继承
- **域隔离**：同一用户在不同域中可以有不同角色

### 2. 继承解析

当检查用户权限时，go-casbin 会：

1. 获取用户的所有直接角色
2. 递归获取所有间接继承的角色
3. 合并所有角色的权限
4. 检查是否匹配请求

### 3. 性能优化

- **缓存机制**：角色继承关系会被缓存，提高查询性能
- **惰性加载**：只在需要时解析继承关系
- **批量操作**：支持批量添加/删除角色继承

## 📝 最佳实践

### 1. 角色设计

- **职责分离**：不同角色对应不同职责
- **层级清晰**：建立清晰的角色层级结构
- **最小权限**：每个角色只包含必要的权限
- **命名规范**：使用清晰的角色命名（如 `admin`、`user`、`viewer`）

### 2. 多租户角色管理

- **域隔离**：使用 RBAC with Domains 模型
- **角色前缀**：为不同租户的角色使用前缀（如 `tenant1_admin`）
- **独立存储**：为每个租户使用独立的角色存储

### 3. 角色变更管理

- **变更日志**：记录角色的创建、修改和删除
- **审批流程**：重要角色变更需要审批
- **权限审计**：定期审计角色权限

### 4. 性能优化

- **合理层级**：避免过深的角色层级
- **批量操作**：使用批量 API 减少数据库操作
- **缓存利用**：依赖缓存提高角色查询性能

## ❓ 常见问题

### Q: 如何处理角色权限冲突？

A: 角色权限冲突通过策略效果评估器解决：

- **白名单模式**：任一角色允许则允许
- **黑名单模式**：没有角色拒绝则允许
- **严格模式**：有允许且无拒绝才允许

### Q: 如何实现角色的动态分配？

A: 
- 基于用户属性动态分配角色
- 使用 ABAC 规则策略模式
- 实现角色分配的业务逻辑

### Q: 如何处理角色的有效期？

A: 
- 在策略中添加时间字段
- 使用 ABAC 规则检查时间条件
- 实现角色过期机制

### Q: 如何实现角色的权限委派？

A: 
- 使用角色继承实现权限委派
- 为委派创建临时角色
- 实现权限委派的审批流程

## 🚀 下一步

- 查看 [多租户指南](multitenancy.md) 掌握多租户隔离方案
- 阅读 [适配器使用指南](adapters.md) 了解各种存储适配器
- 探索 [高级特性指南](advanced-features.md) 掌握企业级功能