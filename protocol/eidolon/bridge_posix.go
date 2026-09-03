//go:build !windows

package eidolon

import (
	"net"
	"os"
	"syscall"
)

func createNativePipe(isQUIC bool) (net.Conn, uintptr, error) {
	sockType := syscall.SOCK_STREAM
	if isQUIC {
		sockType = syscall.SOCK_SEQPACKET
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, sockType, 0)
	if err != nil {
		return nil, 0, err
	}

	f0 := os.NewFile(uintptr(fds[0]), "eidolon_go")
	dataConn, err := net.FileConn(f0)
	f0.Close()
	if err != nil {
		syscall.Close(fds[1])
		return nil, 0, err
	}

	return dataConn, uintptr(fds[1]), nil
}

func closeNativePipeFd(fd uintptr) {
	if fd != 0 {
		syscall.Close(int(fd))
	}
}

// CreateNativePipe creates a native IPC pipe pair for Go and C++ communication.
func CreateNativePipe(isQUIC bool) (net.Conn, uintptr, error) {
	return createNativePipe(isQUIC)
}

// CloseNativePipeFd closes the native pipe file descriptor.
func CloseNativePipeFd(fd uintptr) {
	closeNativePipeFd(fd)
}