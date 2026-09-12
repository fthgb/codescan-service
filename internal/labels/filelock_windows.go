//go:build windows

package labels

import "os"

// Windows stdlib 无可靠 file lock：
//   - syscall 包不导出 LockFile/LockFileEx（仅在 golang.org/x/sys/windows 第三方包，
//     违反无第三方库铁律）；
//   - 尝试 syscall.NewLazyDLL("kernel32.dll") 调 LockFileEx（含 unsafe）对 Go os.File
//     handle 返 ERROR_ACCESS_DENIED(5)，Go non-overlapped handle flags 不兼容。
//
// 跨进程并发保护降级为进程内 sync.Mutex（labels.go writeMu）——HTTP server 单进程
// 部署足够。多进程并发写 labels.jsonl 需 OS 级排他（推 golang.org/x/sys 或外部 lock
// file O_EXCL，超当前纯 stdlib 铁律，留 deferral）。unix 侧 filelock_unix.go 用
// syscall.Flock 提供真正的跨进程锁。
func lockFile(f *os.File) error  { return nil }
func unlockFile(f *os.File) error { return nil }
