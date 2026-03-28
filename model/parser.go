/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\parser.go
 * @Description: 模型解析器（CONF 格式）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"bufio"
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-toolbox/pkg/stringx"
)

func ParseModelFromText(text string) (map[string]*Assertion, error) {
	assertions := make(map[string]*Assertion)
	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := stringx.New(strings.TrimSpace(parts[0])).ToLowerChain().Value()
		value := strings.TrimSpace(parts[1])

		if key == "" || value == "" {
			continue
		}

		assertion := NewAssertion(key, value)
		assertions[key] = assertion
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.NewModelParseFailedError(err.Error())
	}

	return assertions, nil
}

func ParseSectionName(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return strings.TrimSpace(line[1 : len(line)-1])
	}
	return ""
}

func SplitAssertionKey(key string) (section, name string) {
	parts := strings.SplitN(key, "_", 2)
	if len(parts) == 1 {
		return parts[0], parts[0]
	}
	return parts[0], parts[1]
}
