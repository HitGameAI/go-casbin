/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\abac_attribute\main.go
 * @Description: ABAC 属性匹配模式示例
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package main

import (
	"github.com/kamalyes/go-casbin/enforcer"
	"github.com/kamalyes/go-logger"
)

// Resource 资源实体（ABAC 属性匹配模式中 r.obj 的类型）
// 模型 matcher: m = r.sub == r.obj.Owner
// 含义: 只有资源的所有者才能访问
type Resource struct {
	Name  string
	Owner string
}

func main() {
	log := logger.NewLogger().
		WithLevel(logger.INFO).
		WithShowCaller(true)

	e, err := enforcer.NewEnforcer(
		enforcer.WithModelPath("resources/abac_model.conf"),
		enforcer.WithLogger(log),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("=== ABAC 属性匹配模式示例 ===")
	log.InfoKV("模型 matcher", "expr", "m = r.sub == r.obj.Owner")
	log.InfoMsg("含义: 只有资源的所有者才能访问")

	data1 := Resource{Name: "data1", Owner: "alice"}
	data2 := Resource{Name: "data2", Owner: "bob"}

	log.InfoMsg("--- 权限检查 ---")
	checkABAC(log, e, "alice", data1, "read")
	checkABAC(log, e, "bob", data1, "read")
	checkABAC(log, e, "alice", data2, "write")
	checkABAC(log, e, "bob", data2, "write")
}

func checkABAC(log logger.ILogger, e *enforcer.Enforcer, sub string, obj Resource, act string) {
	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.ErrorKV("权限检查异常", "sub", sub, "obj", obj.Name, "act", act, "error", err.Error())
		return
	}
	if ok {
		log.InfoKV("✅ 允许", "sub", sub, "obj", obj.Name, "owner", obj.Owner, "act", act)
	} else {
		log.WarnKV("❌ 拒绝", "sub", sub, "obj", obj.Name, "owner", obj.Owner, "act", act)
	}
}
