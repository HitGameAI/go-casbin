/*
 * @Author: kamalyes 501893067@qq.com
 * @Date: 2025-03-28 00:00:00
 * @LastEditors: kamalyes 501893067@qq.com
 * @LastEditTime: 2025-03-28 00:00:00
 * @FilePath: \go-casbin\model\loader.go
 * @Description: 模型加载器（文件/文本）
 *
 * Copyright (c) 2025 by kamalyes, All Rights Reserved.
 */

package model

import (
	"os"

	"github.com/kamalyes/go-casbin/errors"
)

func LoadModelFromPath(path string) (map[string]*Assertion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.NewModelLoadFailedError(err.Error())
	}
	return ParseModelFromText(string(data))
}

func LoadModelFromText(text string) (map[string]*Assertion, error) {
	return ParseModelFromText(text)
}

func LoadModelFromFile(file *os.File) (map[string]*Assertion, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, errors.NewModelLoadFailedError(err.Error())
	}

	data := make([]byte, stat.Size())
	_, err = file.Read(data)
	if err != nil {
		return nil, errors.NewModelLoadFailedError(err.Error())
	}

	return ParseModelFromText(string(data))
}
