/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\policy\scopes.go
 * @Description: 策略作用域与工具函数 - 提供策略比较、去重、集合运算等通用工具
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package policy

import (
	"sort"
	"strings"
)

// ==================== 策略比较 ====================

// ArrayEquals 判断两个字符串数组是否完全相同
func ArrayEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Array2DEquals 判断两个二维字符串数组是否完全相同
func Array2DEquals(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if !ArrayEquals(v, b[i]) {
			return false
		}
	}
	return true
}

// SortedArray2DEquals 判断两个二维数组排序后是否相同
// 先对两个数组各自排序，再逐行比较
func SortedArray2DEquals(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	copyA := make([][]string, len(a))
	copy(copyA, a)
	copyB := make([][]string, len(b))
	copy(copyB, b)

	SortArray2D(copyA)
	SortArray2D(copyB)

	for i, v := range copyA {
		if !ArrayEquals(v, copyB[i]) {
			return false
		}
	}
	return true
}

// ==================== 排序 ====================

// SortArray2D 对二维字符串数组按字典序排序
func SortArray2D(arr [][]string) {
	if len(arr) == 0 {
		return
	}
	sort.Slice(arr, func(i, j int) bool {
		minLen := len(arr[i])
		if len(arr[j]) < minLen {
			minLen = len(arr[j])
		}
		for k := 0; k < minLen; k++ {
			if arr[i][k] != arr[j][k] {
				return arr[i][k] < arr[j][k]
			}
		}
		return len(arr[i]) < len(arr[j])
	})
}

// ==================== 去重 ====================

// ArrayRemoveDuplicates 原地去重字符串数组
func ArrayRemoveDuplicates(s *[]string) {
	found := make(map[string]bool)
	j := 0
	for i, x := range *s {
		if !found[x] {
			found[x] = true
			(*s)[j] = (*s)[i]
			j++
		}
	}
	*s = (*s)[:j]
}

// RemoveDuplicateElements 返回去重后的新字符串数组
func RemoveDuplicateElements(s []string) []string {
	result := make([]string, 0, len(s))
	seen := make(map[string]struct{})
	for _, item := range s {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// ==================== 集合运算 ====================

// SetEquals 判断两个字符串集合是否相同（忽略顺序）
func SetEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Set2DEquals 判断两个二维字符串集合是否相同（忽略行内顺序和行间顺序）
func Set2DEquals(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}

	var aa []string
	for _, v := range a {
		sort.Strings(v)
		aa = append(aa, strings.Join(v, ", "))
	}
	var bb []string
	for _, v := range b {
		sort.Strings(v)
		bb = append(bb, strings.Join(v, ", "))
	}

	return SetEquals(aa, bb)
}

// SetSubtract 返回在 a 中但不在 b 中的元素（差集）
func SetSubtract(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// ==================== 拼接工具 ====================

// ArrayToString 将字符串数组拼接为逗号分隔的字符串
func ArrayToString(s []string) string {
	return strings.Join(s, ", ")
}

// ParamsToString 将可变参数拼接为逗号分隔的字符串
func ParamsToString(s ...string) string {
	return strings.Join(s, ", ")
}

// JoinSlice 将一个字符串和可变参数拼接为新切片
func JoinSlice(a string, b ...string) []string {
	res := make([]string, 0, len(b)+1)
	res = append(res, a)
	res = append(res, b...)
	return res
}

// JoinSliceAny 将一个字符串和可变参数拼接为 interface{} 切片
func JoinSliceAny(a string, b ...string) []interface{} {
	res := make([]interface{}, 0, len(b)+1)
	res = append(res, a)
	for _, s := range b {
		res = append(res, s)
	}
	return res
}

// ==================== 策略作用域 ====================

// PolicyScope 策略作用域
// 用于定义策略的生效范围，支持按域（租户）、命名空间等维度隔离策略
// 在多租户场景下，不同域的策略互不影响
type PolicyScope struct {
	Domain    string // 域/租户标识（多租户隔离）
	Namespace string // 命名空间（更细粒度的隔离）
	PType     string // 策略类型（p/g/p2/g2 等）
}

// NewPolicyScope 创建策略作用域
func NewPolicyScope(domain, namespace, ptype string) *PolicyScope {
	return &PolicyScope{
		Domain:    domain,
		Namespace: namespace,
		PType:     ptype,
	}
}

// String 返回作用域的字符串表示
// 格式：domain/namespace/ptype
func (ps *PolicyScope) String() string {
	parts := make([]string, 0, 3)
	if ps.Domain != "" {
		parts = append(parts, ps.Domain)
	}
	if ps.Namespace != "" {
		parts = append(parts, ps.Namespace)
	}
	if ps.PType != "" {
		parts = append(parts, ps.PType)
	}
	return strings.Join(parts, "/")
}

// CacheKey 返回作用域对应的缓存键
// 用于在缓存中按作用域索引策略
func (ps *PolicyScope) CacheKey() string {
	return "scope:" + ps.String()
}

// IsGlobal 判断是否为全局作用域（无域和命名空间限制）
func (ps *PolicyScope) IsGlobal() bool {
	return ps.Domain == "" && ps.Namespace == ""
}

// Matches 判断给定策略行是否属于此作用域
func (ps *PolicyScope) Matches(line string) bool {
	if ps.IsGlobal() {
		return true
	}

	filter := NewFilter()
	if ps.PType != "" {
		filter.WithPType(ps.PType)
	}
	if ps.Domain != "" {
		filter.WithV0(ps.Domain)
	}
	return filter.Match(line)
}
