/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\rbac_domains\main.go
 * @Description: 多租户 RBAC 示例 (RBAC with Domains)
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
		enforcer.WithModelPath("resources/rbac_with_domains_model.conf"),
		enforcer.WithPolicyPath("resources/rbac_with_domains_policy.csv"),
		enforcer.WithLogger(log),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("=== 多租户 RBAC 示例 (RBAC with Domains) ===")
	log.InfoMsg("策略说明:")
	log.InfoMsg("  alice 在 tenant1 是 admin → 可读写 data1")
	log.InfoMsg("  alice 在 tenant2 是 viewer → 只能读 data2")
	log.InfoMsg("  bob   在 tenant1 是 viewer → 只能读 data1（但无 viewer 对应策略）")

	log.InfoMsg("--- alice 在 tenant1 (admin) ---")
	checkDomain(log, e, "alice", "tenant1", "data1", "read")
	checkDomain(log, e, "alice", "tenant1", "data1", "write")

	log.InfoMsg("--- alice 在 tenant2 (viewer) ---")
	checkDomain(log, e, "alice", "tenant2", "data2", "read")
	checkDomain(log, e, "alice", "tenant2", "data2", "write")

	log.InfoMsg("--- bob 在 tenant1 (viewer) ---")
	checkDomain(log, e, "bob", "tenant1", "data1", "read")
	checkDomain(log, e, "bob", "tenant1", "data1", "write")

	log.InfoMsg("--- 租户隔离验证 ---")
	log.InfoMsg("  alice 在 tenant1 有 admin 权限，但在 tenant2 没有:")
	checkDomain(log, e, "alice", "tenant2", "data1", "read")
	checkDomain(log, e, "alice", "tenant2", "data1", "write")

	log.InfoMsg("--- 多租户角色管理 API ---")
	roles := e.GetRolesForUserInDomain("alice", "tenant1")
	log.InfoKV("alice 在 tenant1 的角色", "roles", roles)

	roles = e.GetRolesForUserInDomain("alice", "tenant2")
	log.InfoKV("alice 在 tenant2 的角色", "roles", roles)

	perms := e.GetPermissionsForUserInDomain("alice", "tenant1")
	log.InfoKV("alice 在 tenant1 的权限", "permissions", perms)

	perms = e.GetPermissionsForUserInDomain("alice", "tenant2")
	log.InfoKV("alice 在 tenant2 的权限", "permissions", perms)
}

func checkDomain(log logger.ILogger, e *enforcer.Enforcer, sub, dom, obj, act string) {
	ok, err := e.Enforce(sub, dom, obj, act)
	if err != nil {
		log.ErrorKV("权限检查异常", "sub", sub, "domain", dom, "obj", obj, "act", act, "error", err.Error())
		return
	}
	if ok {
		log.InfoKV("✅ 允许", "sub", sub, "domain", dom, "obj", obj, "act", act)
	} else {
		log.WarnKV("❌ 拒绝", "sub", sub, "domain", dom, "obj", obj, "act", act)
	}
}
