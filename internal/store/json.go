package store

import (
	"encoding/json"
	"fmt"
)

// json.go 收敛本模块对 encoding/json 的调用。
//
// 单独一个文件而不是散落各处：本模块的持久化只有一处
// （预编译安装记录），把它收在一处能让"写盘格式变了什么"
// 一眼可见；同时避免每个调用点各写一遍错误包装。

// jsonUnmarshal 解析 JSON。
func jsonUnmarshal(data []byte, dst any) error {
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("store: 解析 JSON 失败: %w", err)
	}
	return nil
}

// jsonMarshalIndent 序列化为带缩进的 JSON（便于人工查看与 git diff）。
func jsonMarshalIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("store: 序列化 JSON 失败: %w", err)
	}
	// 末尾补一个换行：POSIX 文本文件的惯例，也让追加写不会粘行。
	return append(b, '\n'), nil
}
