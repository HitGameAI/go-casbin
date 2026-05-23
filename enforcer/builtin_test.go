/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2026-05-23 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2026-05-23 00:00:00
 * @FilePath: \go-casbin\enforcer\builtin_test.go
 * @Description: 测试内置匹配函数（KeyMatch/RegexMatch/IPMatch/GlobMatch）
 *
 * Copyright (c) 2026 by kamalyes, All Rights Reserved.
 */

package enforcer

import (
	"testing"
)

// ==================== KeyMatch ====================

func TestKeyMatch(t *testing.T) {
	tests := []struct {
		key1, key2 string
		want       bool
	}{
		{"/foo/bar", "/foo/*", true},
		{"/foo/bar", "/foo/baz", false},
		{"/foo", "/foo", true},
		{"/foo", "/bar", false},
		{"/foo/bar/baz", "/foo/*", true},
		{"/foo", "/foo/*", false}, // key1 比 key2 短，无 *
	}

	for _, tt := range tests {
		got := KeyMatch(tt.key1, tt.key2)
		if got != tt.want {
			t.Errorf("KeyMatch(%q, %q) = %v, want %v", tt.key1, tt.key2, got, tt.want)
		}
	}
}

func TestKeyMatchFunc(t *testing.T) {
	result, err := KeyMatchFunc("/foo/bar", "/foo/*")
	if err != nil {
		t.Fatalf("KeyMatchFunc returned error: %v", err)
	}
	if result != true {
		t.Errorf("KeyMatchFunc = %v, want true", result)
	}
}

// ==================== KeyMatch2 ====================

func TestKeyMatch2(t *testing.T) {
	tests := []struct {
		key1, key2 string
		want       bool
	}{
		{"/foo/bar", "/foo/:bar", true},
		{"/foo/bar/baz", "/foo/:bar/baz", true},
		{"/foo/bar", "/foo/*", true},
		{"/foo/bar/baz", "/foo/:bar", false},
	}

	for _, tt := range tests {
		got := KeyMatch2(tt.key1, tt.key2)
		if got != tt.want {
			t.Errorf("KeyMatch2(%q, %q) = %v, want %v", tt.key1, tt.key2, got, tt.want)
		}
	}
}

func TestKeyMatch2Func(t *testing.T) {
	result, err := KeyMatch2Func("/foo/bar", "/foo/:bar")
	if err != nil {
		t.Fatalf("KeyMatch2Func returned error: %v", err)
	}
	if result != true {
		t.Errorf("KeyMatch2Func = %v, want true", result)
	}
}

// ==================== KeyMatch3 ====================

func TestKeyMatch3(t *testing.T) {
	tests := []struct {
		key1, key2 string
		want       bool
	}{
		{"/foo/bar", "/foo/{bar}", true},
		{"/foo/bar/baz", "/foo/{bar}/baz", true},
		{"/foo/bar", "/foo/*", true},
		{"/foo/bar/baz", "/foo/{bar}", false},
	}

	for _, tt := range tests {
		got := KeyMatch3(tt.key1, tt.key2)
		if got != tt.want {
			t.Errorf("KeyMatch3(%q, %q) = %v, want %v", tt.key1, tt.key2, got, tt.want)
		}
	}
}

func TestKeyMatch3Func(t *testing.T) {
	result, err := KeyMatch3Func("/foo/bar", "/foo/{bar}")
	if err != nil {
		t.Fatalf("KeyMatch3Func returned error: %v", err)
	}
	if result != true {
		t.Errorf("KeyMatch3Func = %v, want true", result)
	}
}

// ==================== RegexMatch ====================

func TestRegexMatch(t *testing.T) {
	tests := []struct {
		key1, key2 string
		want       bool
	}{
		{"alice", "^a.*e$", true},
		{"bob", "^a.*e$", false},
		{"/foo/bar", "^/foo/.*$", true},
		{"/foo", "^/bar/.*$", false},
		{"test", "[invalid", false}, // 无效正则应返回 false
	}

	for _, tt := range tests {
		got := RegexMatch(tt.key1, tt.key2)
		if got != tt.want {
			t.Errorf("RegexMatch(%q, %q) = %v, want %v", tt.key1, tt.key2, got, tt.want)
		}
	}
}

func TestRegexMatchFunc(t *testing.T) {
	result, err := RegexMatchFunc("alice", "^a.*e$")
	if err != nil {
		t.Fatalf("RegexMatchFunc returned error: %v", err)
	}
	if result != true {
		t.Errorf("RegexMatchFunc = %v, want true", result)
	}
}

func TestRegexMatch_CacheHit(t *testing.T) {
	// 连续两次相同正则，第二次应命中缓存
	pattern := "^/api/v[0-9]+/.*$"
	_ = RegexMatch("/api/v1/users", pattern)
	// 再次调用，应命中缓存
	got := RegexMatch("/api/v2/orders", pattern)
	if !got {
		t.Errorf("RegexMatch cache hit failed")
	}
}

// ==================== IPMatch ====================

func TestIPMatch(t *testing.T) {
	tests := []struct {
		ip1, ip2 string
		want     bool
	}{
		{"192.168.1.5", "192.168.1.0/24", true},
		{"192.168.2.5", "192.168.1.0/24", false},
		{"192.168.1.5", "192.168.1.5", true},
		{"10.0.0.1", "192.168.1.5", false},
		{"invalid", "192.168.1.0/24", false},
		{"192.168.1.5", "invalid", false},
		{"192.168.1.5", "not-a-cidr/24", false},
	}

	for _, tt := range tests {
		got := IPMatch(tt.ip1, tt.ip2)
		if got != tt.want {
			t.Errorf("IPMatch(%q, %q) = %v, want %v", tt.ip1, tt.ip2, got, tt.want)
		}
	}
}

func TestIPMatchFunc(t *testing.T) {
	result, err := IPMatchFunc("192.168.1.5", "192.168.1.0/24")
	if err != nil {
		t.Fatalf("IPMatchFunc returned error: %v", err)
	}
	if result != true {
		t.Errorf("IPMatchFunc = %v, want true", result)
	}
}

// ==================== GlobMatch ====================

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name, pattern string
		want          bool
	}{
		{"/foo/bar", "/foo/*", true},
		{"/foo/bar.txt", "/foo/*.txt", true},
		{"/foo/bar", "/bar/*", false},
		{"/foo/bar", "[invalid", false}, // 无效 glob 应返回 false
	}

	for _, tt := range tests {
		got := GlobMatch(tt.name, tt.pattern)
		if got != tt.want {
			t.Errorf("GlobMatch(%q, %q) = %v, want %v", tt.name, tt.pattern, got, tt.want)
		}
	}
}

func TestGlobMatchFunc(t *testing.T) {
	result, err := GlobMatchFunc("/foo/bar", "/foo/*")
	if err != nil {
		t.Fatalf("GlobMatchFunc returned error: %v", err)
	}
	if result != true {
		t.Errorf("GlobMatchFunc = %v, want true", result)
	}
}

// ==================== GetBuiltinFunctions ====================

func TestGetBuiltinFunctions(t *testing.T) {
	fns := GetBuiltinFunctions()
	expected := []string{"keyMatch", "keyMatch2", "keyMatch3", "regexMatch", "ipMatch", "globMatch"}

	for _, name := range expected {
		if _, ok := fns[name]; !ok {
			t.Errorf("GetBuiltinFunctions() missing %q", name)
		}
	}

	if len(fns) != len(expected) {
		t.Errorf("GetBuiltinFunctions() returned %d functions, want %d", len(fns), len(expected))
	}
}
