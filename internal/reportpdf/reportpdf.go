// Package reportpdf — 自包含 HTML → PDF（chromedp 驱 Edge/Chrome headless 打印）。
//
// 分层铁律：internal/report 保持纯函数渲染（产 HTML 字符串），本包负责浏览器进程 IO。
// 报告是自包含 HTML（无外部资源/图片/字体），SetDocumentContent 注入后可直接 PrintToPDF。
//
// 打印参数（2026-09-05 用户确认的口径）：
//   - PrintBackground=true：badge/代码块背景色必须保留；
//   - DisplayHeaderFooter=true + 空 header + 仅页码 footer（自定义模板替代浏览器
//     默认的「标题/URL/日期」页眉页脚）；
//   - PreferCSSPageSize=true：让报告模板 @page 的 A4 + mm 边距生效——不开它会被
//     API 默认参数（letter/inch）静默覆盖。
package reportpdf

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// pdfMu —— 串行化导出（令牌桶大小 1 的轻量版）。导出每次起一个临时浏览器实例，
// 脚本批量拉取或连点会 fork 多个浏览器进程瞬间打爆内存；串行排队即可（导出低频）。
// 池化单例 Allocator 是后续优化方向，本期不做。
var pdfMu sync.Mutex

// defaultBrowserCandidates — 默认探测顺序：Edge x86 → Edge x64 → Chrome。
var defaultBrowserCandidates = []string{
	`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	`C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`,
}

// BrowserPath — 解析浏览器可执行路径。优先 env AUDIT_BROWSER_PATH（部署环境无 Edge
// 时的逃生口），缺省按候选列表探测。找不到时返回可操作的错误信息（路由层直接透传给 500）。
func BrowserPath() (string, error) {
	if p := os.Getenv("AUDIT_BROWSER_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("AUDIT_BROWSER_PATH=%q 指向的浏览器不存在", p)
	}
	if runtime.GOOS != "windows" {
		// 非 Windows 无固定安装路径，要求显式指定。
		return "", fmt.Errorf("非 Windows 平台请设置 AUDIT_BROWSER_PATH 指定浏览器可执行文件路径")
	}
	for _, p := range defaultBrowserCandidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("未探测到可用浏览器（Edge/Chrome），请设置 AUDIT_BROWSER_PATH 指定浏览器可执行文件路径")
}

// footerTemplate — 仅页码（页脚 margin 区绘制，样式 8px 居中灰字）。
// pageNumber/totalPages 是 Chromium 页眉页脚模板的专用 class。
const footerTemplate = `<div style="font-size:8px; width:100%; text-align:center; color:#888;">
<span class="pageNumber"></span> / <span class="totalPages"></span></div>`

// RenderPDF — HTML 字符串 → PDF 字节。每次调用起一个临时 headless 实例（低频导出，
// 不做进程池），60s 超时，互斥串行。
func RenderPDF(html string) ([]byte, error) {
	pdfMu.Lock()
	defer pdfMu.Unlock()

	exe, err := BrowserPath()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(exe),
		chromedp.Flag("headless", "new"),
		chromedp.NoSandbox,
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	var pdf []byte
	err = chromedp.Run(browserCtx, chromedp.Tasks{
		chromedp.Navigate("about:blank"),
		// SetDocumentContent 注入完整文档（不用 data: URL——大报告会超 URL 长度限制）。
		chromedp.ActionFunc(func(ctx context.Context) error {
			tree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return fmt.Errorf("get frame tree: %w", err)
			}
			return page.SetDocumentContent(tree.Frame.ID, html).Do(ctx)
		}),
		// 报告无外部资源（样式内联、无图片/字体），SetDocumentContent 同步替换后
		// 文档即就位，无需额外等待，直接打印。
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithDisplayHeaderFooter(true).
				WithHeaderTemplate(`<div></div>`).
				WithFooterTemplate(footerTemplate).
				WithPreferCSSPageSize(true).
				Do(ctx)
			if err != nil {
				return fmt.Errorf("print to pdf: %w", err)
			}
			pdf = buf
			return nil
		}),
	})
	if err != nil {
		return nil, err
	}
	if len(pdf) == 0 {
		return nil, fmt.Errorf("print to pdf returned empty buffer")
	}
	return pdf, nil
}
