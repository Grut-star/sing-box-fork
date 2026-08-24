package eidolon

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}/lib -leidolon_net -lstdc++
#include "bridge.h"
#include <stdlib.h>
#include <stdint.h>

// Модифицированные сигнатуры C для передачи data_fd как uintptr_t (безопасно для Windows SOCKET)
// extern EidolonHandle eidolon_dial_tcp(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
// extern EidolonHandle eidolon_dial_quic(const char* host, uint16_t port, const uint8_t* token, size_t token_len, uintptr_t data_fd);
// extern int eidolon_export_key(EidolonHandle handle, uint8_t* out_key, size_t key_len);
// extern void eidolon_close(EidolonHandle handle);
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"
)

// NativeStackConn реализует стандартный интерфейс net.Conn,
// но физически I/O операции идут через платформозависимый пайп напрямую в ядро Chromium.
type NativeStackConn struct {
	handle     C.EidolonHandle
	dataConn   net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

// DialNativeTCP устанавливает TLS 1.3 соединение через стек Chromium.
func DialNativeTCP(ctx context.Context, host string, port int, token []byte) (*NativeStackConn, error) {
	return dialNative(ctx, host, port, token, false)
}

// DialNativeQUIC устанавливает HTTP/3 QUIC соединение через стек Chromium.
func DialNativeQUIC(ctx context.Context, host string, port int, token []byte) (*NativeStackConn, error) {
	return dialNative(ctx, host, port, token, true)
}

// Главная фабрика соединений
func dialNative(ctx context.Context, host string, port int, token []byte, isQUIC bool) (*NativeStackConn, error) {
	// 1. Создаем платформозависимый канал связи (Socketpair для POSIX, Loopback TCP для Windows)
	dataConn, cFdPtr, err := createNativePipe(isQUIC)
	if err != nil {
		return nil, fmt.Errorf("eidolon bridge: failed to create native pipe: %w", err)
	}

	// 2. Готовим аргументы для CGO
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	var cToken *C.uint8_t
	if len(token) > 0 {
		cToken = (*C.uint8_t)(unsafe.Pointer(&token[0]))
	}

	// Приводим дескриптор к безопасному для Windows и POSIX типу uintptr_t
	cFd := C.uintptr_t(cFdPtr)

	// 3. Выполняем дозвон асинхронно, чтобы уважать context.Context
	type dialResult struct {
		handle C.EidolonHandle
		err    error
	}
	resCh := make(chan dialResult, 1)

	go func() {
		var handle C.EidolonHandle
		if isQUIC {
			handle = C.eidolon_dial_quic(cHost, C.uint16_t(port), cToken, C.size_t(len(token)), cFd)
		} else {
			handle = C.eidolon_dial_tcp(cHost, C.uint16_t(port), cToken, C.size_t(len(token)), cFd)
		}

		if handle == nil {
			resCh <- dialResult{nil, errors.New("native stack: dial failed inside C++")}
			return
		}
		resCh <- dialResult{handle, nil}
	}()

	// 4. Ожидаем завершения с учетом контекста
	select {
	case <-ctx.Done():
		// Если контекст отменен (таймаут/прерывание), жестко закрываем сокет.
		// Это заставит C++ ядро получить ошибку записи/чтения и освободить ресурсы.
		dataConn.Close()
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			dataConn.Close()
			return nil, res.err
		}

		// Сохраняем адреса на этапе создания для корректной работы sing-box ядра
		return &NativeStackConn{
			handle:     res.handle,
			dataConn:   dataConn,
			localAddr:  dataConn.LocalAddr(),
			remoteAddr: dataConn.RemoteAddr(),
		}, nil
	}
}

// ExportKeyingMaterial запрашивает 32 байта ключа для TLS Exporter из C++
func (c *NativeStackConn) ExportKeyingMaterial() ([]byte, error) {
	key := make([]byte, 32)
	cKey := (*C.uint8_t)(unsafe.Pointer(&key[0]))

	res := C.eidolon_export_key(c.handle, cKey, C.size_t(len(key)))
	if res != 0 {
		return nil, errors.New("native stack: failed to export keying material")
	}
	return key, nil
}

// -------------------------------------------------------------------------
// Реализация интерфейса net.Conn (Data Plane)
// -------------------------------------------------------------------------

// Read и Write больше не используют CGO. Они работают через асинхронный epoll/IOCP Go.
func (c *NativeStackConn) Read(b []byte) (n int, err error) {
	return c.dataConn.Read(b)
}

func (c *NativeStackConn) Write(b []byte) (n int, err error) {
	return c.dataConn.Write(b)
}

func (c *NativeStackConn) Close() error {
	// 1. Закрываем dataConn: это немедленно разблокирует все ждущие Read/Write в Go.
	err := c.dataConn.Close()

	// 2. Сигнализируем C++ ядру освободить память и закрыть Chromium-сокет.
	if c.handle != nil {
		C.eidolon_close(c.handle)
		c.handle = nil
	}
	return err
}

func (c *NativeStackConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *NativeStackConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *NativeStackConn) SetDeadline(t time.Time) error      { return c.dataConn.SetDeadline(t) }
func (c *NativeStackConn) SetReadDeadline(t time.Time) error  { return c.dataConn.SetReadDeadline(t) }
func (c *NativeStackConn) SetWriteDeadline(t time.Time) error { return c.dataConn.SetWriteDeadline(t) }