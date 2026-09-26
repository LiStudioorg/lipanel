//go:build linux || android

package sysinfo

import "testing"

// TestInt8ArrayToString 验证 uname(2) 返回的定长 int8 数组转字符串的逻辑。
//
// 该测试必须放在 Linux/Android 构建标签下：utsArrayToString 只在
// host_linux.go 中定义（其它平台的 Utsname 字段类型不同，甚至是 [N]byte）。
func TestInt8ArrayToString(t *testing.T) {
	// 用 [65]T 定长数组（与 syscall.Utsname 的字段形状一致）。
	var raw [65]int8
	copy(raw[:], []int8{'x', '8', '6', '_', '6', '4'})
	if got := utsArrayToString(raw); got != "x86_64" {
		t.Errorf("utsArrayToString = %q, 期望 %q", got, "x86_64")
	}

	// uint8 形态（arm/ppc64/riscv64/s390x 上 Utsname 的字段类型）。
	var rawU [65]uint8
	copy(rawU[:], []uint8{'a', 'r', 'm', '6', '4'})
	if got := utsArrayToString(rawU); got != "arm64" {
		t.Errorf("utsArrayToString(uint8) = %q, 期望 %q", got, "arm64")
	}

	var empty [65]int8
	if got := utsArrayToString(empty); got != "" {
		t.Errorf("全零输入应返回空串，实际 %q", got)
	}
}
