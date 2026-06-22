/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\enforcer_bench_test.go
 * @Description: 执行器性能基准测试
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"fmt"
	"testing"

	"github.com/kamalyes/go-casbin/model"
	"github.com/kamalyes/go-casbin/policy"
	"github.com/kamalyes/go-logger"
)

// 测试用 matcher 表达式常量
const benchMatcherACL = "r.sub == p.sub && r.obj == p.obj && r.act == p.act"

// ==================== 正则缓存基准测试 ====================

// BenchmarkRegexMatch_Cached 测试 RegexMatch 在缓存命中时的性能
func BenchmarkRegexMatch_Cached(b *testing.B) {
	// 预热缓存
	RegexMatch("/api/users/123", "^/api/users/[^/]+$")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RegexMatch("/api/users/123", "^/api/users/[^/]+$")
	}
}

// BenchmarkKeyMatch3_Cached 测试 KeyMatch3 在缓存命中时的性能
func BenchmarkKeyMatch3_Cached(b *testing.B) {
	// 预热缓存
	KeyMatch3("/api/users/123", "/api/users/{id}")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KeyMatch3("/api/users/123", "/api/users/{id}")
	}
}

// BenchmarkKeyMatch2_Cached 测试 KeyMatch2 在缓存命中时的性能
func BenchmarkKeyMatch2_Cached(b *testing.B) {
	// 预热缓存
	KeyMatch2("/api/users/123", "/api/users/:id")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KeyMatch2("/api/users/123", "/api/users/:id")
	}
}

// BenchmarkKeyMatch_Simple 测试 KeyMatch（无正则，纯字符串比较）
func BenchmarkKeyMatch_Simple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		KeyMatch("/api/users/123", "/api/*")
	}
}

// ==================== 多策略 Enforce 基准测试 ====================

// buildBenchmarkEnforcer 构建用于基准测试的 Enforcer（使用静默日志避免干扰 benchmark 输出）
func buildBenchmarkEnforcer(b *testing.B, policyCount int) *Enforcer {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
	var policies []string
	for i := 0; i < policyCount; i++ {
		role := fmt.Sprintf("role:admin_%03d", i)
		policies = append(policies, fmt.Sprintf("p, %s, ops, /api/resource%d, *", role, i))
		policies = append(policies, fmt.Sprintf("p, %s, ops, /api/resource%d/{id}, *", role, i))
		policies = append(policies, fmt.Sprintf("g, user_%03d, %s, ops", i, role))
	}

	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy(policies)
	if err != nil {
		b.Fatal(err)
	}

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(false),
		WithEnabled(true),
		WithLogger(logger.NoLogger), // 静默日志，避免干扰 benchmark 输出
	)
	if err != nil {
		b.Fatal(err)
	}
	return e
}

// BenchmarkEnforce_SmallPolicySet 小规模策略集（10 条策略）
func BenchmarkEnforce_SmallPolicySet(b *testing.B) {
	e := buildBenchmarkEnforcer(b, 5)
	defer e.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Enforce("user_000", "ops", "/api/resource0", "GET")
	}
}

// BenchmarkEnforce_MediumPolicySet 中等规模策略集（100 条策略）
func BenchmarkEnforce_MediumPolicySet(b *testing.B) {
	e := buildBenchmarkEnforcer(b, 50)
	defer e.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Enforce("user_000", "ops", "/api/resource0", "GET")
	}
}

// BenchmarkEnforce_LargePolicySet 大规模策略集（500 条策略）
func BenchmarkEnforce_LargePolicySet(b *testing.B) {
	e := buildBenchmarkEnforcer(b, 250)
	defer e.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Enforce("user_000", "ops", "/api/resource0", "GET")
	}
}

// BenchmarkEnforce_Parallel 并发 Enforce 基准测试
func BenchmarkEnforce_Parallel(b *testing.B) {
	e := buildBenchmarkEnforcer(b, 50)
	defer e.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			user := fmt.Sprintf("user_%03d", i%50)
			e.Enforce(user, "ops", "/api/resource0", "GET")
			i++
		}
	})
}

// ==================== EffectEvaluator 缓存基准测试 ====================

// BenchmarkEffectEvaluation_Cached 测试缓存的 EffectEvaluator 性能
func BenchmarkEffectEvaluation_Cached(b *testing.B) {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch3(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
	memAdapter := policy.NewMemoryAdapter()
	err := memAdapter.SavePolicy([]string{
		"p, role:admin, ops, /api/users, *",
		"g, user001, role:admin, ops",
	})
	if err != nil {
		b.Fatal(err)
	}

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(false),
		WithEnabled(true),
		WithLogger(logger.NoLogger),
	)
	if err != nil {
		b.Fatal(err)
	}
	defer e.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Enforce("user001", "ops", "/api/users", "GET")
	}
}

// ==================== BatchEnforce 基准测试 ====================

// BenchmarkBatchEnforce 测试批量 Enforce 性能
func BenchmarkBatchEnforce(b *testing.B) {
	e := buildBenchmarkEnforcer(b, 50)
	defer e.Close()

	requests := make([][]interface{}, 100)
	for i := 0; i < 100; i++ {
		requests[i] = []interface{}{"user_000", "ops", "/api/resource0", "GET"}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.BatchEnforce(requests)
	}
}

// ==================== MatcherEngine 基准测试 ====================

// BenchmarkMatcherEngine_Match_ACL ACL 模式匹配基准测试
func BenchmarkMatcherEngine_Match_ACL(b *testing.B) {
	me := NewMatcherEngine(logger.NoLogger)
	assertion := &model.Assertion{Tokens: []string{"p.sub", "p.obj", "p.act"}}

	mc := &MatchContext{
		Request: map[string]interface{}{
			"r.sub": "alice", "r.obj": "data1", "r.act": "read",
		},
		Policies: [][]string{
			{"alice", "data1", "read"},
			{"bob", "data2", "write"},
			{"charlie", "data3", "read"},
		},
		Assertion:   assertion,
		CustomFuncs: map[string]BuiltinFunc{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		me.Match(mc, benchMatcherACL)
	}
}

// ==================== GetPermissionsInDomains 基准测试 ====================

// buildDomainBenchmarkEnforcer 构建多域基准测试 Enforcer
func buildDomainBenchmarkEnforcer(b *testing.B, domainCount, policiesPerDomain int) *Enforcer {
	modelText := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.obj == p.obj && r.act == p.act
`
	var policies []string
	for d := 0; d < domainCount; d++ {
		domain := fmt.Sprintf("tenant_%03d", d)
		for p := 0; p < policiesPerDomain; p++ {
			role := fmt.Sprintf("role_%03d", p)
			policies = append(policies, fmt.Sprintf("p, %s, %s, resource_%03d, read", role, domain, p))
			policies = append(policies, fmt.Sprintf("p, %s, %s, resource_%03d, write", role, domain, p))
		}
		policies = append(policies, fmt.Sprintf("g, test_user, role_000, %s", domain))
	}

	memAdapter := policy.NewMemoryAdapter()
	if err := memAdapter.SavePolicy(policies); err != nil {
		b.Fatal(err)
	}

	e, err := NewEnforcer(
		WithModelText(modelText),
		WithAdapter(memAdapter),
		WithAutoSave(false),
		WithEnabled(true),
		WithLogger(logger.NoLogger),
	)
	if err != nil {
		b.Fatal(err)
	}
	return e
}

// BenchmarkGetPermissionsInDomains_Small 小规模（5域×10策略/域）
func BenchmarkGetPermissionsInDomains_Small(b *testing.B) {
	e := buildDomainBenchmarkEnforcer(b, 5, 10)
	defer e.Close()

	queries := make([]DomainQuery, 5)
	for i := 0; i < 5; i++ {
		queries[i] = DomainQuery{Subject: "role_000", Domain: fmt.Sprintf("tenant_%03d", i)}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.GetPermissionsInDomains(queries)
	}
}

// BenchmarkGetPermissionsInDomains_Medium 中等规模（20域×50策略/域）
func BenchmarkGetPermissionsInDomains_Medium(b *testing.B) {
	e := buildDomainBenchmarkEnforcer(b, 20, 50)
	defer e.Close()

	queries := make([]DomainQuery, 20)
	for i := 0; i < 20; i++ {
		queries[i] = DomainQuery{Subject: "role_000", Domain: fmt.Sprintf("tenant_%03d", i)}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.GetPermissionsInDomains(queries)
	}
}

// BenchmarkGetPermissionsInDomains_Large 大规模（50域×100策略/域）
func BenchmarkGetPermissionsInDomains_Large(b *testing.B) {
	e := buildDomainBenchmarkEnforcer(b, 50, 100)
	defer e.Close()

	queries := make([]DomainQuery, 50)
	for i := 0; i < 50; i++ {
		queries[i] = DomainQuery{Subject: "role_000", Domain: fmt.Sprintf("tenant_%03d", i)}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.GetPermissionsInDomains(queries)
	}
}

// BenchmarkGetPermissionsForUserInDomain_Loop 逐域调用旧方法作为对比基准
func BenchmarkGetPermissionsForUserInDomain_Loop(b *testing.B) {
	e := buildDomainBenchmarkEnforcer(b, 20, 50)
	defer e.Close()

	domains := make([]string, 20)
	for i := 0; i < 20; i++ {
		domains[i] = fmt.Sprintf("tenant_%03d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, d := range domains {
			e.GetPermissionsForUserInDomain("role_000", d)
		}
	}
}

// BenchmarkMatcherEngine_Match_ShortCircuit 短路优化基准测试
func BenchmarkMatcherEngine_Match_ShortCircuit(b *testing.B) {
	me := NewMatcherEngine(logger.NoLogger)
	assertion := &model.Assertion{Tokens: []string{"p.sub", "p.obj", "p.act", "p.eft"}}

	var policies [][]string
	for i := 0; i < 100; i++ {
		policies = append(policies, []string{"alice", "data1", "read", "allow"})
	}

	mc := &MatchContext{
		Request:      map[string]interface{}{"r.sub": "alice", "r.obj": "data1", "r.act": "read"},
		Policies:     policies,
		Assertion:    assertion,
		CustomFuncs:  map[string]BuiltinFunc{},
		ShortCircuit: true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		me.Match(mc, benchMatcherACL)
	}
}
