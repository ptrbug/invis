// +build freebsd netbsd openbsd

package crash

import (
	"os"
	"syscall"
)

var globalFile *os.File

func InitPanicFile(panicFile string) error {
	file, err := os.OpenFile(panicFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
	if err != nil {
		return err
	}
	globalFile = file
	if err = syscall.Dup2(int(file.Fd()), int(os.Stderr.Fd())); err != nil {
		return err
	}
	return nil
}
