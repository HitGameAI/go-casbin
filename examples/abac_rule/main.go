/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\abac_rule\main.go
 * @Description: ABAC 规则策略模式示例
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
		enforcer.WithModelPath("resources/abac_rule_model.conf"),
		enforcer.WithPolicyPath("resources/abac_rule_policy.csv"),
		enforcer.WithLogger(log),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("=== ABAC 规则策略模式示例 ===")
	log.InfoKV("模型 matcher", "expr", "m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act")
	log.InfoMsg("策略文件中的条件表达式:")
	log.InfoMsg("  p, r.sub == \"alice\", data1, read       → 等于判断")
	log.InfoMsg("  p, r.sub == \"bob\",   data2, write      → 等于判断")
	log.InfoMsg("  p, r.sub != \"eve\",   data3, read       → 不等于判断")
	log.InfoMsg("  p, r.sub in (\"alice\",\"bob\"), data4, read → 包含判断")

	log.InfoMsg("--- 等于判断 (r.sub == \"alice\") ---")
	check(log, e, "alice", "data1", "read")
	check(log, e, "bob", "data1", "read")

	log.InfoMsg("--- 等于判断 (r.sub == \"bob\") ---")
	check(log, e, "bob", "data2", "write")
	check(log, e, "alice", "data2", "write")

	log.InfoMsg("--- 不等于判断 (r.sub != \"eve\") ---")
	check(log, e, "alice", "data3", "read")
	check(log, e, "eve", "data3", "read")

	log.InfoMsg("--- 包含判断 (r.sub in (\"alice\", \"bob\")) ---")
	check(log, e, "alice", "data4", "read")
	check(log, e, "bob", "data4", "read")
	check(log, e, "eve", "data4", "read")

	log.InfoMsg("--- 动态添加 ABAC 规则 ---")
	if err := e.AddPolicy(`r.sub == "dave"`, "data6", "write"); err != nil {
		log.WarnKV("策略已存在，跳过添加", "error", err.Error())
	} else {
		log.InfoMsg("成功添加策略: r.sub == \"dave\", data6, write")
	}
	check(log, e, "dave", "data6", "write")
	check(log, e, "alice", "data6", "write")
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
