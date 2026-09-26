// Package lipanel 是模块根包，唯一的职责是承载前端的 go:embed 资源。
//
// 为什么必须放在模块根目录：
// go:embed 的路径是相对「声明该指令的包所在目录」解析的，且不能使用 ../
// 向上跨目录。前端产物位于 web/dist，因此本包必须在仓库根目录。
// internal/server 等子包通过 import "lipanel" 使用这里导出的文件系统。
package lipanel

import (
	"embed"
	"io/fs"
)

// distFS 承载 web/dist 下的全部前端产物。
// all: 前缀让以 _ 或 . 开头的文件（如 Vite 可能产出的 .vite 目录）也被打包。
//
//go:embed all:web/dist
var distFS embed.FS

// WebFS 返回以 web/dist 为根的文件系统，可直接交给 http.FS 使用。
// 例如 fsys.Open("index.html") 对应 web/dist/index.html。
func WebFS() (fs.FS, error) {
	return fs.Sub(distFS, "web/dist")
}

// WebBuilt 判断前端产物是否已真实构建。
// 以 index.html 是否存在为准：仅有占位文件 web/dist/.gitkeep 时返回 false，
// 以便启动阶段给出「请先构建前端」的明确提示，而不是返回空白页面。
func WebBuilt() bool {
	f, err := distFS.Open("web/dist/index.html")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
