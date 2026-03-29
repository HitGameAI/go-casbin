/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\rbac_basic\main.go
 * @Description: RBAC 基本使用示例
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package main

import (
	"github.com/kamalyes/go-casbin/enforcer"
	"github.com/kamalyes/go-logger"
)

func main() {
	log := logger.NewLogger().
		WithLevel(logger.INFO).
		WithShowCaller(true)

	e, err := enforcer.NewEnforcer(
		enforcer.WithModelPath("resources/rbac_model.conf"),
		enforcer.WithPolicyPath("resources/rbac_policy.csv"),
		enforcer.WithLogger(log),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("=== RBAC 基本使用示例 ===")

	log.InfoMsg("--- 权限检查 ---")
	check(log, e, "alice", "data1", "read")
	check(log, e, "alice", "data1", "write")
	check(log, e, "bob", "data2", "read")
	check(log, e, "bob", "data1", "write")

	log.InfoMsg("--- 角色查询 ---")
	roles := e.GetRolesForUser("alice")
	log.InfoKV("alice 的角色", "roles", roles)

	perms := e.GetPermissionsForUser("admin")
	log.InfoKV("admin 的权限", "permissions", perms)

	log.InfoMsg("--- 动态添加策略 ---")
	if err := e.AddPolicy("bob", "data1", "write"); err != nil {
		log.ErrorKV("添加策略失败", "error", err.Error())
	}
	check(log, e, "bob", "data1", "write")

	log.InfoMsg("--- 动态删除策略 ---")
	if err := e.RemovePolicy("bob", "data1", "write"); err != nil {
		log.ErrorKV("删除策略失败", "error", err.Error())
	}
	check(log, e, "bob", "data1", "write")
}

func check(log logger.ILogger, e *enforcer.Enforcer, sub, obj, act string) {
	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.ErrorKV("权限检查异常", "sub", sub, "obj", obj, "act", act, "error", err.Error())
		return
	}
	if ok {
		log.InfoKV("✅ 允许", "sub", sub, "obj", obj, "act", act)
	} else {
		log.WarnKV("❌ 拒绝", "sub", sub, "obj", obj, "act", act)
	}
}
