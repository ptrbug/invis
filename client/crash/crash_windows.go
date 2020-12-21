// +build windows

package crash

import (
	"os"
	"syscall"
)

const (
	kernel32dll = "kernel32.dll"
)

var globalFile *os.File

//InitPanicFile init panic file
func InitPanicFile(panicFile string) error {
	file, err := os.OpenFile(panicFile, os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		return err
	}
	globalFile = file
	kernel32 := syscall.NewLazyDLL(kernel32dll)
	setStdHandle := kernel32.NewProc("SetStdHandle")
	sh := syscall.STD_ERROR_HANDLE
	v, _, err := setStdHandle.Call(uintptr(sh), uintptr(file.Fd()))
	if v == 0 {
		return err
	}
	return nil
}
