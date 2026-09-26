package file

import (
	"strings"
	"testing"
)

// ============================================================================
// 权限判定与审计测试（阶段四 4.2）
// ============================================================================

func TestRequiredPermission(t *testing.T) {
	read := []string{ActionList, ActionRead, ActionDownload}
	for _, a := range read {
		if got := RequiredPermission(a); got != PermRead {
			t.Errorf("动作 %s 需要 %s，实际 %s", a, PermRead, got)
		}
	}
	write := []string{ActionWrite, ActionMkdir, ActionUpload, ActionRename, ActionDelete}
	for _, a := range write {
		if got := RequiredPermission(a); got != PermWrite {
			t.Errorf("动作 %s 需要 %s，实际 %s", a, PermWrite, got)
		}
	}
}

func TestIsWriteAction(t *testing.T) {
	// 这条判定决定了"哪些操作要记审计"，写错会让删除操作悄悄不留痕。
	if IsWriteAction(ActionList) || IsWriteAction(ActionRead) || IsWriteAction(ActionDownload) {
		t.Error("读操作不应被判为写操作")
	}
	for _, a := range []string{ActionWrite, ActionMkdir, ActionUpload, ActionRename, ActionDelete} {
		if !IsWriteAction(a) {
			t.Errorf("%s 必须被判为写操作（否则不记审计）", a)
		}
	}
	// 未知动作按写处理：宁可多记一条审计，也不要漏记。
	if !IsWriteAction("something-new") {
		t.Error("未知动作应按写操作处理（默认从严）")
	}
}

func TestCheckFilePermission(t *testing.T) {
	admin := AdminGrantee("admin")

	t.Run("管理员读操作放行", func(t *testing.T) {
		d := CheckFilePermission(admin, ActionList)
		if !d.Allowed || d.Required != PermRead {
			t.Fatalf("应放行且 required=file.read，实际 %+v", d)
		}
	})

	t.Run("管理员写操作放行", func(t *testing.T) {
		d := CheckFilePermission(admin, ActionDelete)
		if !d.Allowed || d.Required != PermWrite {
			t.Fatalf("应放行且 required=file.write，实际 %+v", d)
		}
	})

	t.Run("只读用户写操作被拒", func(t *testing.T) {
		viewer := Grantee{User: "viewer", Granted: []string{PermRead}}
		d := CheckFilePermission(viewer, ActionDelete)
		if d.Allowed {
			t.Fatal("只读用户的删除必须被拒绝")
		}
		// 拒绝原因必须点出"谁""缺什么权限"，否则用户无从判断。
		if !strings.Contains(d.Reason, "viewer") || !strings.Contains(d.Reason, PermWrite) {
			t.Fatalf("拒绝原因应含用户名与所需权限，实际 %q", d.Reason)
		}
		if d.Hint == "" {
			t.Fatal("必须给出 hint（怎么办），否则用户只看到一句拒绝")
		}
		// 应当回显已授予的权限，便于对照排查。
		if len(d.Granted) != 1 || d.Granted[0] != PermRead {
			t.Fatalf("应回显已授予权限，实际 %v", d.Granted)
		}
	})

	t.Run("只读用户读操作仍放行", func(t *testing.T) {
		viewer := Grantee{User: "viewer", Granted: []string{PermRead}}
		if d := CheckFilePermission(viewer, ActionDownload); !d.Allowed {
			t.Fatalf("只读用户应能下载，实际 %+v", d)
		}
	})

	t.Run("无任何权限时全拒", func(t *testing.T) {
		none := Grantee{User: "nobody"}
		for _, a := range []string{ActionList, ActionRead, ActionDelete} {
			if d := CheckFilePermission(none, a); d.Allowed {
				t.Errorf("零权限用户不应能执行 %s", a)
			}
		}
	})

	t.Run("空用户名也能给出可读原因", func(t *testing.T) {
		d := CheckFilePermission(Grantee{}, ActionWrite)
		if !strings.Contains(d.Reason, "当前用户") {
			t.Fatalf("应回落到「当前用户」，实际 %q", d.Reason)
		}
	})
}

func TestGranteeHasIsCaseInsensitive(t *testing.T) {
	g := Grantee{Granted: []string{" File.Write ", "file.READ"}}
	if !g.Has(PermWrite) || !g.Has(PermRead) {
		t.Fatal("权限匹配应忽略大小写与首尾空白")
	}
	if g.Has("file.execute") {
		t.Fatal("未授予的权限不应命中")
	}
}

func TestAdminGranteeCopiesPermissions(t *testing.T) {
	// 返回的切片若被调用方原地修改，会影响后续所有判定（单管理员模式下
	// 等于"一次意外修改永久提权/降权"）。这里锁死"返回的是副本"。
	d := CheckFilePermission(AdminGrantee("admin"), ActionList)
	d.Granted[0] = "tampered"

	again := CheckFilePermission(AdminGrantee("admin"), ActionList)
	if again.Granted[0] == "tampered" {
		t.Fatal("Granted 必须是副本，不能被调用方通过返回值篡改")
	}
}
