/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\enforcer\builtin.go
 * @Description: 内置匹配函数（KeyMatch/RegexMatch/IPMatch/GlobMatch）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// BuiltinFunc 内置匹配函数类型
// 所有内置函数（KeyMatch/RegexMatch/IPMatch/GlobMatch）都遵循此签名
// 参数为可变参数列表，返回匹配结果和可能的错误
type BuiltinFunc func(args ...interface{}) (interface{}, error)

// regexCache 全局正则编译缓存，避免每次 Enforce 重复编译相同的正则表达式
// key 为正则表达式字符串，value 为编译后的 *regexp.Regexp
// 对于策略数量大（数百条）的场景，缓存命中率极高，可减少 90%+ 的正则编译开销
var regexCache sync.Map

// getCompiledRegexp 从缓存获取或编译正则表达式
func getCompiledRegexp(pattern string) (*regexp.Regexp, error) {
	if re, ok := regexCache.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// paramPatternRe 预编译的路径参数匹配正则（:param 风格）
var paramPatternRe = regexp.MustCompile(`:[^/]+`)

// braceParamPatternRe 预编译的路径参数匹配正则（{param} 风格）
var braceParamPatternRe = regexp.MustCompile(`\{[^/]+\}`)

// normalizeKeyMatchPath 规范 KeyMatch 路径参数，移除查询参数和尾部斜杠
// 例如：/foo/bar → /foo/bar
// 例如：/foo/bar?query → /foo/bar
// 例如：/ → /
func normalizeKeyMatchPath(key string, trimTrailingSlash bool) string {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "/") {
		return key
	}
	if idx := strings.IndexByte(key, '?'); idx >= 0 {
		key = key[:idx]
	}
	if trimTrailingSlash && key != "/" {
		key = strings.TrimRight(key, "/")
	}
	if key == "" {
		return "/"
	}
	return key
}

// hasWildcardPathSuffix 检查路径是否以 /* 结尾，用于 KeyMatch 匹配
// 例如：/foo/bar → false
// 例如：/foo/* → true
// 例如：/foo/bar/baz → false
func hasWildcardPathSuffix(key string) bool {
	key = strings.TrimSpace(key)
	if idx := strings.IndexByte(key, '?'); idx >= 0 {
		key = key[:idx]
	}
	return strings.HasSuffix(key, "/*")
}

// KeyMatch 路径通配符匹配（简易版）
// 仅支持 * 通配符，匹配前缀部分
// 例如：KeyMatch("/foo/bar", "/foo/*") → true
// 例如：KeyMatch("/foo/bar", "/foo/baz") → false
func KeyMatch(key1, key2 string) bool {
	trimRequestTrailingSlash := !hasWildcardPathSuffix(key2)
	key1 = normalizeKeyMatchPath(key1, trimRequestTrailingSlash)
	key2 = normalizeKeyMatchPath(key2, true)
	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}
	if len(key1) > i {
		return key1[:i] == key2[:i]
	}
	return key1 == key2[:i]
}

// KeyMatchFunc KeyMatch 的表达式函数包装
// 用于在 matcher 表达式中以 keyMatch(key1, key2) 形式调用
func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch(name1, name2), nil
}

// KeyMatch2 路径通配符匹配（增强版）
// 支持 :param 风格的路径参数匹配，将 :param 转换为正则 [^/]+
// 例如：KeyMatch2("/foo/bar", "/foo/:bar") → true
// 例如：KeyMatch2("/foo/bar/baz", "/foo/*") → true（/* 转为 /.*）
// 例如：KeyMatch2("/foo/bar", "*") → true（纯 * 匹配所有路径）
func KeyMatch2(key1, key2 string) bool {
	if key2 == "*" {
		return true
	}
	trimRequestTrailingSlash := !hasWildcardPathSuffix(key2)
	key1 = normalizeKeyMatchPath(key1, trimRequestTrailingSlash)
	key2 = normalizeKeyMatchPath(key2, true)
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = paramPatternRe.ReplaceAllString(key2, "$1[^/]+$2")
	return RegexMatch(key1, "^"+key2+"$")
}

// KeyMatch2Func KeyMatch2 的表达式函数包装
// 用于在 matcher 表达式中以 keyMatch2(key1, key2) 形式调用
func KeyMatch2Func(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch2(name1, name2), nil
}

// KeyMatch3 路径通配符匹配（花括号版）
// 支持 {param} 风格的路径参数匹配，将 {param} 转换为正则 [^/]+
// 例如：KeyMatch3("/foo/bar", "/foo/{bar}") → true
// 例如：KeyMatch3("/foo/bar", "*") → true（纯 * 匹配所有路径）
// 与 KeyMatch2 类似，但使用花括号而非冒号表示路径参数
func KeyMatch3(key1, key2 string) bool {
	if key2 == "*" {
		return true
	}
	trimRequestTrailingSlash := !hasWildcardPathSuffix(key2)
	key1 = normalizeKeyMatchPath(key1, trimRequestTrailingSlash)
	key2 = normalizeKeyMatchPath(key2, true)
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = braceParamPatternRe.ReplaceAllString(key2, "[^/]+")
	return RegexMatch(key1, "^"+key2+"$")
}

// KeyMatch3Func KeyMatch3 的表达式函数包装
// 用于在 matcher 表达式中以 keyMatch3(key1, key2) 形式调用
func KeyMatch3Func(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch3(name1, name2), nil
}

// RegexMatch 正则表达式匹配
// key2 为正则表达式模式，key1 为待匹配字符串
// 例如：RegexMatch("alice", "^a.*e$") → true
// 例如：RegexMatch("/foo/bar", "^/foo/.*$") → true
func RegexMatch(key1, key2 string) bool {
	re, err := getCompiledRegexp(key2)
	if err != nil {
		return false
	}
	return re.MatchString(key1)
}

// RegexMatchFunc RegexMatch 的表达式函数包装
// 用于在 matcher 表达式中以 regexMatch(key1, key2) 形式调用
func RegexMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return RegexMatch(name1, name2), nil
}

// IPMatch IP 地址匹配
// 支持两种模式：
//   - CIDR 模式：ip2 为 CIDR 表示法（如 "192.168.1.0/24"），判断 ip1 是否在该子网内
//   - 精确匹配：ip2 为单个 IP 地址，判断两者是否相同
//
// 例如：IPMatch("192.168.1.5", "192.168.1.0/24") → true
// 例如：IPMatch("192.168.1.5", "192.168.1.5") → true
// 例如：IPMatch("10.0.0.1", "192.168.1.0/24") → false
func IPMatch(ip1, ip2 string) bool {
	objIP1 := net.ParseIP(ip1)
	if objIP1 == nil {
		return false
	}

	if strings.Contains(ip2, "/") {
		_, ipnet, err := net.ParseCIDR(ip2)
		if err != nil {
			return false
		}
		return ipnet.Contains(objIP1)
	}

	objIP2 := net.ParseIP(ip2)
	if objIP2 == nil {
		return false
	}
	return objIP1.Equal(objIP2)
}

// IPMatchFunc IPMatch 的表达式函数包装
// 用于在 matcher 表达式中以 ipMatch(ip1, ip2) 形式调用
func IPMatchFunc(args ...interface{}) (interface{}, error) {
	ip1 := args[0].(string)
	ip2 := args[1].(string)
	return IPMatch(ip1, ip2), nil
}

// GlobMatch Glob 模式匹配
// 使用 filepath.Match 进行文件通配符匹配
// 支持 *（匹配任意非分隔符序列）、?（匹配单个字符）、[...]（字符范围）
// 例如：GlobMatch("/foo/bar", "/foo/*") → true
// 例如：GlobMatch("/foo/bar.txt", "/foo/*.txt") → true
func GlobMatch(name, pattern string) bool {
	matched, err := filepath.Match(pattern, name)
	if err != nil {
		return false
	}
	return matched
}

// GlobMatchFunc GlobMatch 的表达式函数包装
// 用于在 matcher 表达式中以 globMatch(name, pattern) 形式调用
func GlobMatchFunc(args ...interface{}) (interface{}, error) {
	name := args[0].(string)
	pattern := args[1].(string)
	return GlobMatch(name, pattern), nil
}

// GetBuiltinFunctions 获取所有内置匹配函数的映射表
// 返回的 map 可直接注入到匹配器引擎中，在 matcher 表达式中使用函数名调用
// 支持的函数：
//   - keyMatch:   路径前缀通配符匹配（* 通配）
//   - keyMatch2:  路径参数匹配（:param 风格）
//   - keyMatch3:  路径参数匹配（{param} 风格）
//   - regexMatch: 正则表达式匹配
//   - ipMatch:    IP 地址/CIDR 匹配
//   - globMatch:  Glob 模式匹配
func GetBuiltinFunctions() map[string]BuiltinFunc {
	return map[string]BuiltinFunc{
		"keyMatch":   KeyMatchFunc,
		"keyMatch2":  KeyMatch2Func,
		"keyMatch3":  KeyMatch3Func,
		"regexMatch": RegexMatchFunc,
		"ipMatch":    IPMatchFunc,
		"globMatch":  GlobMatchFunc,
	}
}
