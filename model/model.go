/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\model.go
 * @Description: 核心模型定义与操作
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"strings"

	"github.com/kamalyes/go-casbin/errors"
	"github.com/kamalyes/go-logger"
	"github.com/kamalyes/go-toolbox/pkg/syncx"
)

type Model struct {
	assertions map[string]*Assertion
	logger     logger.ILogger
}

func NewModel(log logger.ILogger) *Model {
	return &Model{
		assertions: make(map[string]*Assertion),
		logger:     log,
	}
}

func NewModelFromText(text string, log logger.ILogger) (*Model, error) {
	m := NewModel(log)
	if err := m.LoadFromText(text); err != nil {
		return nil, err
	}
	return m, nil
}

func NewModelFromPath(path string, log logger.ILogger) (*Model, error) {
	m := NewModel(log)
	if err := m.LoadFromPath(path); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Model) LoadFromText(text string) error {
	assertions, err := LoadModelFromText(text)
	if err != nil {
		return err
	}

	if err := ValidateModel(assertions); err != nil {
		return err
	}

	m.assertions = assertions
	m.logger.InfoKV("Model loaded from text", "sections", len(assertions))
	return nil
}

func (m *Model) LoadFromPath(path string) error {
	assertions, err := LoadModelFromPath(path)
	if err != nil {
		return errors.WrapError("LoadFromPath", err)
	}

	if err := ValidateModel(assertions); err != nil {
		return err
	}

	m.assertions = assertions
	m.logger.InfoKV("Model loaded from file", "path", path, "sections", len(assertions))
	return nil
}

func (m *Model) GetAssertion(key string) *Assertion {
	return m.assertions[key]
}

func (m *Model) GetAssertions() map[string]*Assertion {
	return m.assertions
}

func (m *Model) AddDef(key, value string) error {
	assertion := NewAssertion(key, value)
	m.assertions[key] = assertion
	m.logger.DebugKV("Definition added", "key", key, "value", value)
	return nil
}

func (m *Model) HasSection(section string) bool {
	for key := range m.assertions {
		if strings.HasPrefix(key, section) {
			return true
		}
	}
	return false
}

func (m *Model) GetValuesForFieldInPolicyAllTypes(section, field string) [][]string {
	var values [][]string
	for key, assertion := range m.assertions {
		if strings.HasPrefix(key, section) {
			fieldIndex := -1
			for i, token := range assertion.Tokens {
				if token == field {
					fieldIndex = i
					break
				}
			}
			if fieldIndex >= 0 {
				for _, policy := range assertion.Policies {
					if fieldIndex < len(policy) {
						values = append(values, policy)
					}
				}
			}
		}
	}
	return values
}

func (m *Model) Copy() *Model {
	newModel := NewModel(m.logger)
	copied := make(map[string]*Assertion, len(m.assertions))
	if err := syncx.DeepCopy(&copied, &m.assertions); err != nil {
		for k, v := range m.assertions {
			copied[k] = v
		}
	}
	newModel.assertions = copied
	return newModel
}

func (m *Model) ToText() string {
	var sb strings.Builder

	writeSection := func(section string) {
		for key, assertion := range m.assertions {
			if strings.HasPrefix(key, section) {
				sb.WriteString(key)
				sb.WriteString(" = ")
				sb.WriteString(assertion.Value)
				sb.WriteString("\n")
			}
		}
	}

	sections := []string{SectionRequestDefinition, SectionPolicyDefinition, SectionRoleDefinition, SectionPolicyEffect, SectionMatchers}
	for _, section := range sections {
		if m.HasSection(section) {
			sb.WriteString("[")
			sb.WriteString(section)
			sb.WriteString("]\n")
			writeSection(section)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (m *Model) ClearPolicies() {
	for _, assertion := range m.assertions {
		assertion.ClearPolicies()
	}
	m.logger.DebugMsg("All policies cleared from model")
}
