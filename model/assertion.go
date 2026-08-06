/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\assertion.go
 * @Description: 断言定义（r/p/g/e/m 模型段）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"strings"

	"github.com/kamalyes/go-toolbox/pkg/stringx"
)

const (
	SectionRequestDefinition = "r"
	SectionPolicyDefinition  = "p"
	SectionRoleDefinition    = "g"
	SectionPolicyEffect      = "e"
	SectionMatchers          = "m"
)

type Assertion struct {
	Key       string
	Value     string
	Tokens    []string
	Policies  [][]string
	PolicyMap map[string]int
}

func NewAssertion(key, value string) *Assertion {
	a := &Assertion{
		Key:       key,
		Value:     strings.TrimSpace(value),
		PolicyMap: make(map[string]int),
	}
	a.buildTokens()
	return a
}

func (a *Assertion) buildTokens() {
	if a.Value == "" {
		a.Tokens = nil
		return
	}
	parts := strings.Split(a.Value, ",")
	a.Tokens = make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			a.Tokens = append(a.Tokens, a.Key+"."+t)
		}
	}
}

func (a *Assertion) AddPolicy(policy []string) {
	key := strings.Join(policy, ",")
	if _, exists := a.PolicyMap[key]; exists {
		return
	}
	a.Policies = append(a.Policies, policy)
	a.PolicyMap[key] = len(a.Policies) - 1
}

func (a *Assertion) RemovePolicy(policy []string) bool {
	key := strings.Join(policy, ",")
	idx, exists := a.PolicyMap[key]
	if !exists {
		return false
	}
	a.Policies = append(a.Policies[:idx], a.Policies[idx+1:]...)
	delete(a.PolicyMap, key)
	a.RebuildPolicyMap()
	return true
}

func (a *Assertion) HasPolicy(policy []string) bool {
	key := strings.Join(policy, ",")
	_, exists := a.PolicyMap[key]
	return exists
}

func (a *Assertion) ClearPolicies() {
	a.Policies = nil
	a.PolicyMap = make(map[string]int)
}

// RebuildPolicyMap 重建 PolicyMap（用于批量修改 Policies 后一次性重建索引）
// 导出方法：供 policy 层在 in-place 批量增删后调用，替代逐条 AddPolicy 的 N 次 strings.Join
func (a *Assertion) RebuildPolicyMap() {
	if a.PolicyMap == nil {
		a.PolicyMap = make(map[string]int, len(a.Policies))
	} else {
		for k := range a.PolicyMap {
			delete(a.PolicyMap, k)
		}
	}
	for i, p := range a.Policies {
		a.PolicyMap[strings.Join(p, ",")] = i
	}
}

func (a *Assertion) BuildRoleLinkCondition(name1, name2 string) string {
	return stringx.New(name1).Value() + ":" + stringx.New(name2).Value()
}
