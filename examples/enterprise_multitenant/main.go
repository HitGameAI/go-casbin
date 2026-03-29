/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\examples\enterprise_multitenant\main.go
 * @Description: 企业级多租户示例（无外部依赖版）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package main

import (
	"time"

	"github.com/kamalyes/go-casbin/enforcer"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/breaker"
	"github.com/kamalyes/go-toolbox/pkg/retry"
)

func main() {
	log := logger.NewLogger().
		WithLevel(logger.INFO).
		WithShowCaller(true)

	log.InfoMsg("=== 企业级多租户示例（无外部依赖版） ===")
	log.InfoMsg("本示例演示 options 组合使用:")
	log.InfoMsg("  - WithModelPath + WithPolicyPath: 模型和策略文件")
	log.InfoMsg("  - WithBreaker: 熔断保护")
	log.InfoMsg("  - WithRetry: 自动重试")
	log.InfoMsg("  - WithAutoSave: 自动保存策略变更")
	log.InfoMsg("  - WithEnabled: 启用执行器")

	e, err := enforcer.NewEnforcer(
		enforcer.WithModelPath("resources/abac_rule_model.conf"),
		enforcer.WithPolicyPath("resources/abac_rule_policy.csv"),
		enforcer.WithLogger(log),
		enforcer.WithBreaker("casbin-tenant1", breaker.Config{
			MaxFailures:  5,
			ResetTimeout: 30 * time.Second,
		}),
		enforcer.WithRetry(
			retry.NewRetry().
				SetAttemptCount(3).
				SetInterval(100*time.Millisecond).
				SetBackoffMultiplier(2.0),
		),
		enforcer.WithAutoSave(true),
		enforcer.WithEnabled(true),
	)
	if err != nil {
		log.Fatal("Failed to create enforcer: %v", err)
	}

	log.InfoMsg("--- ABAC 规则策略权限检查 ---")
	check(log, e, "alice", "data1", "read")
	check(log, e, "bob", "data2", "write")
	check(log, e, "eve", "data3", "read")

	log.InfoMsg("--- 动态添加策略（自动保存） ---")
	if err := e.AddPolicy(`r.sub == "dave"`, "data6", "write"); err != nil {
		log.WarnKV("策略已存在，跳过添加", "error", err.Error())
	} else {
		log.InfoMsg("成功添加策略: r.sub == \"dave\", data6, write")
	}
	check(log, e, "dave", "data6", "write")

	log.InfoMsg("--- 多租户工厂模式示例 ---")
	log.InfoMsg("  实际项目中，每个租户创建独立的 Enforcer:")

	tenant1 := createTenantEnforcer("tenant1", log)
	tenant2 := createTenantEnforcer("tenant2", log)

	log.InfoMsg("  tenant1 (RBAC with Domains):")
	checkDomain(log, tenant1, "alice", "tenant1", "data1", "read")
	checkDomain(log, tenant1, "alice", "tenant1", "data1", "write")

	log.InfoMsg("  tenant2 (RBAC with Domains):")
	checkDomain(log, tenant2, "alice", "tenant2", "data2", "read")
	checkDomain(log, tenant2, "alice", "tenant2", "data2", "write")

	log.InfoMsg("--- 完整企业级示例需要外部依赖 ---")
	log.InfoMsg("  以下功能需要 MySQL/Redis/Kafka/NATS 等外部服务:")
	log.InfoMsg("  - WithAdapter(ormAdapter)      → 需要 MySQL/PostgreSQL")
	log.InfoMsg("  - WithNotifier(redisNotifier)  → 需要 Redis")
	log.InfoMsg("  - WithNotifier(kafkaNotifier)  → 需要 Kafka")
	log.InfoMsg("  - WithNotifier(natsNotifier)   → 需要 NATS")
	log.InfoMsg("  完整示例代码见: examples/enterprise_full/main.go")
}

func createTenantEnforcer(tenantID string, log logger.ILogger) *enforcer.Enforcer {
	e, err := enforcer.NewEnforcer(
		enforcer.WithModelPath("resources/rbac_with_domains_model.conf"),
		enforcer.WithPolicyPath("resources/rbac_with_domains_policy.csv"),
		enforcer.WithLogger(log),
		enforcer.WithBreaker("casbin-"+tenantID, breaker.Config{
			MaxFailures:  5,
			ResetTimeout: 30 * time.Second,
		}),
		enforcer.WithAutoSave(true),
	)
	if err != nil {
		log.Fatal("Failed to create tenant enforcer: %v", err)
	}
	return e
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

func checkDomain(log logger.ILogger, e *enforcer.Enforcer, sub, dom, obj, act string) {
	ok, err := e.Enforce(sub, dom, obj, act)
	if err != nil {
		log.ErrorKV("权限检查异常", "sub", sub, "domain", dom, "obj", obj, "act", act, "error", err.Error())
		return
	}
	if ok {
		log.InfoKV("    ✅ 允许", "sub", sub, "domain", dom, "obj", obj, "act", act)
	} else {
		log.WarnKV("    ❌ 拒绝", "sub", sub, "domain", dom, "obj", obj, "act", act)
	}
}

var _ = policy.WithChannel
