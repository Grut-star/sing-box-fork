//go:build windows

package eidolon

import (
	"net"
)

func createNativePipe(isQUIC bool) (net.Conn, uintptr, error) {
	// В Windows мы не можем использовать Unix-сокеты для передачи в C++,
	// поэтому создаем петлевое TCP-соединение (Local Loopback).
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	defer listener.Close()

	var cppConn net.Conn
	acceptErr := make(chan error, 1)
	go func() {
		var err error
		cppConn, err = listener.Accept()
		acceptErr <- err
	}()

	goConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, 0, err
	}

	if err := <-acceptErr; err != nil {
		goConn.Close()
		return nil, 0, err
	}

	// Извлекаем "сырой" системный дескриптор для передачи в C++
	sysConn, err := cppConn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return nil, 0, err
	}

	var fd uintptr
	sysConn.Control(func(f uintptr) {
		fd = f
	})

	return goConn, fd, nil
}