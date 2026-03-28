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
)

type BuiltinFunc func(args ...interface{}) (interface{}, error)

func KeyMatch(key1, key2 string) bool {
	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}
	if len(key1) > i {
		return key1[:i] == key2[:i]
	}
	return key1 == key2[:i]
}

func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch(name1, name2), nil
}

func KeyMatch2(key1, key2 string) bool {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	re := regexp.MustCompile(`:[^/]+`)
	key2 = re.ReplaceAllString(key2, "$1[^/]+$2")
	return RegexMatch(key1, "^"+key2+"$")
}

func KeyMatch2Func(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch2(name1, name2), nil
}

func KeyMatch3(key1, key2 string) bool {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	re := regexp.MustCompile(`\{[^/]+\}`)
	key2 = re.ReplaceAllString(key2, "[^/]+")
	return RegexMatch(key1, "^"+key2+"$")
}

func KeyMatch3Func(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return KeyMatch3(name1, name2), nil
}

func RegexMatch(key1, key2 string) bool {
	re, err := regexp.Compile(key2)
	if err != nil {
		return false
	}
	return re.MatchString(key1)
}

func RegexMatchFunc(args ...interface{}) (interface{}, error) {
	name1 := args[0].(string)
	name2 := args[1].(string)
	return RegexMatch(name1, name2), nil
}

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

func IPMatchFunc(args ...interface{}) (interface{}, error) {
	ip1 := args[0].(string)
	ip2 := args[1].(string)
	return IPMatch(ip1, ip2), nil
}

func GlobMatch(name, pattern string) bool {
	matched, err := filepath.Match(pattern, name)
	if err != nil {
		return false
	}
	return matched
}

func GlobMatchFunc(args ...interface{}) (interface{}, error) {
	name := args[0].(string)
	pattern := args[1].(string)
	return GlobMatch(name, pattern), nil
}

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
