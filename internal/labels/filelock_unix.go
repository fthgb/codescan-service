//go:build !windows

package labels

import (
	"os"
	"syscall"
)

// lockFile 获取排他文件锁（阻塞直到获取）。Unix 用 syscall.Flock LOCK_EX。
//
// 锁关联 open file description（非 fd），*os.File 生命周期内有效。
// close 自动释放锁，但调用方显式 unlockFile 更清晰（defer LIFO 保证
// unlock 先于 Close 执行，语义明确）。
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// unlockFile 释放排他锁（syscall.Flock LOCK_UN）。
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
