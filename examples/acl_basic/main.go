/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\acl_basic\main.go
 * @Description: ACL 基本使用示例
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
		enforcer.WithModelPath("resources/acl_model.conf"),
		enforcer.WithPolicyPath("resources/acl_policy.csv"),
		enforcer.WithLogger(log),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("=== ACL 基本使用示例 ===")
	log.InfoMsg("ACL 特点: 用户直接绑定资源权限，没有角色概念")
	log.InfoMsg("策略: alice 可读写 data1, bob 只能读 data2")

	log.InfoMsg("--- 权限检查 ---")
	check(log, e, "alice", "data1", "read")
	check(log, e, "alice", "data1", "write")
	check(log, e, "bob", "data2", "read")
	check(log, e, "bob", "data1", "read")
	check(log, e, "alice", "data2", "read")

	log.InfoMsg("--- 与 RBAC 对比 ---")
	log.InfoMsg("  ACL:  r.sub == p.sub（用户直接匹配，没有角色层）")
	log.InfoMsg("  RBAC: g(r.sub, p.sub)（通过角色间接匹配）")
	log.WarnMsg("  ACL 适合小型系统，用户多时策略爆炸")
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
