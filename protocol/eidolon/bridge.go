package eidolon

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo android,arm64 LDFLAGS: -L${SRCDIR}/lib/arm64-v8a -leidolon -lstdc++ -lm
#cgo android,arm LDFLAGS: -L${SRCDIR}/lib/armeabi-v7a -leidolon -lstdc++ -lm
#cgo android,amd64 LDFLAGS: -L${SRCDIR}/lib/x86_64 -leidolon -lstdc++ -lm
#cgo android,386 LDFLAGS: -L${SRCDIR}/lib/x86 -leidolon -lstdc++ -lm
#cgo !android LDFLAGS: -L${SRCDIR}/lib -leidolon -lstdc++ -lm
#include "bridge.h"
#include <stdlib.h>
#include <stdint.h>

extern void eidolon_init();

// EIDOLON_DIAG: регистрируем Go-колбэк защиты сокета (определён через //export в protect_export.go).
// Колбэк зовёт Android VpnService.protect на fd нативного сокета до connect.
extern int eidolonProtectFd(int fd);
static void eidolon_register_protect(void) { eidolon_set_protect(eidolonProtectFd); }

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
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	activeHandlesMu sync.Mutex
	activeHandles   = make(map[uintptr]struct{})
)

func registerActiveHandle(h C.EidolonHandle) {
	if h == nil {
		return
	}
	activeHandlesMu.Lock()
	activeHandles[uintptr(h)] = struct{}{}
	activeHandlesMu.Unlock()
}

func safeCloseHandle(h C.EidolonHandle) bool {
	if h == nil {
		C.eidolon_close(nil)
		return false
	}
	u := uintptr(h)
	activeHandlesMu.Lock()
	_, exists := activeHandles[u]
	if exists {
		delete(activeHandles, u)
	}
	activeHandlesMu.Unlock()

	if exists {
		C.eidolon_close(h)
		return true
	}
	return false
}

// EidolonClose safely closes a raw EidolonHandle with idempotency, double-close protection, and invalid handle checking.
func EidolonClose(handle unsafe.Pointer) bool {
	return safeCloseHandle(C.EidolonHandle(handle))
}

// CloseHandle is an alias for EidolonClose.
func CloseHandle(handle unsafe.Pointer) bool {
	return safeCloseHandle(C.EidolonHandle(handle))
}

// RawDialTCP invokes C.eidolon_dial_tcp directly for boundary stress testing.
func RawDialTCP(host string, port int, token []byte, dataFd uintptr) unsafe.Pointer {
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	safeToken := token
	if len(safeToken) < 32 {
		safeToken = make([]byte, 32)
		copy(safeToken, token)
	}

	var cToken *C.uint8_t
	if len(safeToken) > 0 {
		cToken = (*C.uint8_t)(unsafe.Pointer(&safeToken[0]))
	}

	h := C.eidolon_dial_tcp(cHost, C.uint16_t(port), cToken, C.size_t(len(safeToken)), C.uintptr_t(dataFd))
	if h != nil {
		registerActiveHandle(h)
	}
	return unsafe.Pointer(h)
}

// RawDialQUIC invokes C.eidolon_dial_quic directly for boundary stress testing.
func RawDialQUIC(host string, port int, token []byte, dataFd uintptr) unsafe.Pointer {
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	var cToken *C.uint8_t
	if len(token) > 0 {
		cToken = (*C.uint8_t)(unsafe.Pointer(&token[0]))
	}

	h := C.eidolon_dial_quic(cHost, C.uint16_t(port), cToken, C.size_t(len(token)), C.uintptr_t(dataFd))
	if h != nil {
		registerActiveHandle(h)
	}
	return unsafe.Pointer(h)
}

// EidolonDialTCP is an alias for RawDialTCP.
func EidolonDialTCP(host string, port int, token []byte, dataFd uintptr) unsafe.Pointer {
	return RawDialTCP(host, port, token, dataFd)
}

// EidolonDialQUIC is an alias for RawDialQUIC.
func EidolonDialQUIC(host string, port int, token []byte, dataFd uintptr) unsafe.Pointer {
	return RawDialQUIC(host, port, token, dataFd)
}

// RawDialBoundaryStress directly invokes C.eidolon_dial_tcp or C.eidolon_dial_quic with raw pointers and
// explicit lengths, verifying that the CGO bridge safely bounds-checks parameters (e.g. nil pointers with non-zero lengths)
// to prevent out-of-bounds memory access.
func RawDialBoundaryStress(isQUIC bool, host string, port int, tokenPtr unsafe.Pointer, tokenLen int, dataFd uintptr) unsafe.Pointer {
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))

	// CGO bounds validation: if tokenPtr is nil, ensure tokenLen is 0 to prevent null buffer over-reads
	if tokenPtr == nil {
		tokenLen = 0
	}

	var h C.EidolonHandle
	if isQUIC {
		h = C.eidolon_dial_quic(cHost, C.uint16_t(port), (*C.uint8_t)(tokenPtr), C.size_t(tokenLen), C.uintptr_t(dataFd))
	} else {
		h = C.eidolon_dial_tcp(cHost, C.uint16_t(port), (*C.uint8_t)(tokenPtr), C.size_t(tokenLen), C.uintptr_t(dataFd))
	}
	if h != nil {
		registerActiveHandle(h)
	}
	return unsafe.Pointer(h)
}

func init() {
    // Гарантирует, что среда Chromium инициализируется один раз при старте
    C.eidolon_init()
    // Регистрируем нативный колбэк защиты сокета (сама функция protect ставится позже
    // через SetProtectFunc, когда известен platform interface бокса).
    C.eidolon_register_protect()
}

// globalProtect хранит функцию защиты сокета (Android VpnService.protect через platform interface).
// Доступ из нативного колбэка eidolonProtectFd (protect_export.go).
var globalProtect atomic.Pointer[func(fd int) error]

// SetProtectFunc задаёт функцию защиты исходящих сокетов нативного стека.
// Передай nil, чтобы снять (на платформах без VpnService protect не нужен).
func SetProtectFunc(f func(fd int) error) {
	if f == nil {
		globalProtect.Store(nil)
		return
	}
	globalProtect.Store(&f)
}

// NativeStackConn реализует стандартный интерфейс net.Conn,
// но физически I/O операции идут через платформозависимый пайп напрямую в ядро Chromium.
type NativeStackConn struct {
	closeMu    sync.RWMutex
	closed     bool
	handle     C.EidolonHandle
	dataConn   net.Conn
	// Фаза 4: ненадёжный датаграм-канал (MoQT datagram-objects). nil для TCP/QUIC
	// и для MoQT-сессий без датаграм-lane. Кадрирование [len:2 BE][payload].
	datagramConn net.Conn
	dgramWriteMu sync.Mutex
	localAddr    net.Addr
	remoteAddr   net.Addr
}

// RawHandle returns the underlying EidolonHandle as an unsafe.Pointer (for testing and diagnostic introspection).
func (c *NativeStackConn) RawHandle() unsafe.Pointer {
	if c == nil {
		return nil
	}
	c.closeMu.RLock()
	defer c.closeMu.RUnlock()
	return unsafe.Pointer(c.handle)
}

// Migrate переносит несущее QUIC/MoQT-соединение на другую сеть Android
// (Wi-Fi<->сота) без разрыва туннеля. networkHandle — Network.getNetworkHandle()
// из ConnectivityManager. No-op для закрытых и не-MoQT соединений (нативная
// сторона сама игнорирует не-MoQT handle).
func (c *NativeStackConn) Migrate(networkHandle int64) {
	if c == nil {
		return
	}
	c.closeMu.RLock()
	defer c.closeMu.RUnlock()
	if c.closed || c.handle == nil {
		return
	}
	C.eidolon_migrate(c.handle, C.int64_t(networkHandle))
}

// HasDatagramLane сообщает, поднят ли ненадёжный датаграм-канал (MoQT datagram-objects).
func (c *NativeStackConn) HasDatagramLane() bool {
	if c == nil {
		return false
	}
	c.closeMu.RLock()
	defer c.closeMu.RUnlock()
	return c.datagramConn != nil && !c.closed
}

// WriteDatagram отправляет одну датаграмму (уже зашифрованный кодеком кадр) в
// нативный слой — она уйдёт одним MoQT datagram-object. Кадр [len:2 BE][payload].
// Потокобезопасно (несколько UDP-флоу делят один канал).
func (c *NativeStackConn) WriteDatagram(p []byte) error {
	if c == nil {
		return errors.New("eidolon: nil conn")
	}
	if len(p) == 0 {
		return nil
	}
	if len(p) > 0xFFFF {
		return errors.New("eidolon: datagram too large to frame")
	}
	c.closeMu.RLock()
	dc := c.datagramConn
	closed := c.closed
	c.closeMu.RUnlock()
	if closed || dc == nil {
		return errors.New("eidolon: datagram lane unavailable")
	}
	buf := make([]byte, 2+len(p))
	buf[0] = byte(len(p) >> 8)
	buf[1] = byte(len(p))
	copy(buf[2:], p)
	c.dgramWriteMu.Lock()
	defer c.dgramWriteMu.Unlock()
	_, err := dc.Write(buf) // net.Conn.Write пишет буфер целиком или возвращает ошибку
	return err
}

// ReadDatagram читает одну входящую датаграмму (кадр [len:2 BE][payload]) из
// нативного слоя. Блокирующий; рассчитан на одного читателя (демукс-горутину сессии).
func (c *NativeStackConn) ReadDatagram() ([]byte, error) {
	if c == nil {
		return nil, errors.New("eidolon: nil conn")
	}
	c.closeMu.RLock()
	dc := c.datagramConn
	c.closeMu.RUnlock()
	if dc == nil {
		return nil, errors.New("eidolon: no datagram lane")
	}
	var hdr [2]byte
	if _, err := io.ReadFull(dc, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(dc, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// nativeTransport выбирает несущий транспорт нативного стека.
type nativeTransport int

const (
	transportTCP nativeTransport = iota
	transportQUIC
	transportMoQT
)

// DialNativeTCP устанавливает TLS 1.3 соединение через стек Chromium.
func DialNativeTCP(ctx context.Context, host string, port int, token []byte) (*NativeStackConn, error) {
	return dialNative(ctx, host, port, token, transportTCP)
}

// DialNativeQUIC устанавливает HTTP/3 QUIC соединение через стек Chromium.
func DialNativeQUIC(ctx context.Context, host string, port int, token []byte) (*NativeStackConn, error) {
	return dialNative(ctx, host, port, token, transportQUIC)
}

// DialNativeMoQT устанавливает MoQT (WebTransport-over-H3) соединение через стек Chromium.
func DialNativeMoQT(ctx context.Context, host string, port int, token []byte) (*NativeStackConn, error) {
	return dialNative(ctx, host, port, token, transportMoQT)
}

// Главная фабрика соединений
func dialNative(ctx context.Context, host string, port int, token []byte, transport nativeTransport) (*NativeStackConn, error) {
	// 1. Создаем платформозависимый канал связи (Socketpair для POSIX, Loopback TCP для Windows)
	dataConn, cFdPtr, err := createNativePipe(transport != transportTCP)
	if err != nil {
		return nil, fmt.Errorf("eidolon bridge: failed to create native pipe: %w", err)
	}

	// Фаза 4: для MoQT поднимаем ВТОРОЙ канал — ненадёжный датаграм-lane (UDP).
	// Кадрирование [len:2 BE][payload] поверх STREAM-пайпа; на натив идёт как
	// второй FD. Для TCP/QUIC датаграм-канала нет (datagram_fd=0).
	var datagramConn net.Conn
	var cFd2Ptr uintptr
	if transport == transportMoQT {
		datagramConn, cFd2Ptr, err = createNativePipe(true)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("eidolon bridge: failed to create datagram pipe: %w", err)
		}
	}

	// 2. Готовим аргументы для CGO
	cHost := C.CString(host)

	// TCP: здесь теперь передаётся мастер-секрет (переменной длины), а сам токен
	// nonce||tag считает BoringSSL над key_share. QUIC: 32-байтный токен nonce||tag.
	// Дополнять нулями НЕЛЬЗЯ — это изменило бы секрет и сломало HMAC.
	safeToken := token

	var cToken *C.uint8_t
	if len(safeToken) > 0 {
		cToken = (*C.uint8_t)(unsafe.Pointer(&safeToken[0]))
	}

	// Приводим дескриптор к безопасному для Windows и POSIX типу uintptr_t
	cFd := C.uintptr_t(cFdPtr)
	cFd2 := C.uintptr_t(cFd2Ptr) // датаграм-FD (0 для не-MoQT)

	// 3. Выполняем дозвон асинхронно, чтобы уважать context.Context
	type dialResult struct {
		handle C.EidolonHandle
		err    error
	}
	resCh := make(chan dialResult, 1)

	go func() {
		defer C.free(unsafe.Pointer(cHost))
		var handle C.EidolonHandle
		switch transport {
		case transportMoQT:
			handle = C.eidolon_dial_moqt(cHost, C.uint16_t(port), cToken, C.size_t(len(safeToken)), cFd, cFd2)
		case transportQUIC:
			handle = C.eidolon_dial_quic(cHost, C.uint16_t(port), cToken, C.size_t(len(safeToken)), cFd)
		default:
			handle = C.eidolon_dial_tcp(cHost, C.uint16_t(port), cToken, C.size_t(len(safeToken)), cFd)
		}

		if handle == nil {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
			case resCh <- dialResult{nil, errors.New("native stack: dial failed inside C++")}:
			}
			return
		}

		registerActiveHandle(handle)

		if ctx.Err() != nil {
			safeCloseHandle(handle)
			return
		}

		select {
		case <-ctx.Done():
			safeCloseHandle(handle)
		case resCh <- dialResult{handle, nil}:
		}
	}()

	// 4. Ожидаем завершения с учетом контекста
	select {
	case <-ctx.Done():
		select {
		case res := <-resCh:
			if res.handle != nil {
				safeCloseHandle(res.handle)
			}
		default:
		}
		dataConn.Close()
		if datagramConn != nil {
			datagramConn.Close()
		}
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			dataConn.Close()
			if datagramConn != nil {
				datagramConn.Close()
			}
			return nil, res.err
		}

		// Сохраняем адреса на этапе создания для корректной работы sing-box ядра
		return &NativeStackConn{
			handle:       res.handle,
			dataConn:     dataConn,
			datagramConn: datagramConn,
			localAddr:    dataConn.LocalAddr(),
			remoteAddr:   dataConn.RemoteAddr(),
		}, nil
	}
}

func ListenNativeQUIC(ctx context.Context, host string, port int, secret []byte, onAccept func(net.Conn, []byte, []byte)) error {
	return listenNative(ctx, host, port, secret, onAccept, nil, transportQUIC)
}

// ListenNativeMoQT поднимает серверный MoQT (WebTransport-over-H3) слушатель через стек
// Chromium. Мост к локальному ядру и валидация токена идентичны QUIC-пути (80-байтовая meta).
// onDatagram (Фаза 4, может быть nil) — обработчик ненадёжного датаграм-lane: натив
// коннектит второй cb_port, шлёт meta(80)=token‖key‖flowID(zeros), далее кадры
// [len:2 BE][payload]; conn отдаётся обработчику ПОСЛЕ чтения meta.
func ListenNativeMoQT(ctx context.Context, host string, port int, secret []byte, onAccept func(net.Conn, []byte, []byte), onDatagram func(conn net.Conn, sessionKey []byte)) error {
	return listenNative(ctx, host, port, secret, onAccept, onDatagram, transportMoQT)
}

// acceptMetaLoop принимает соединения от натива, читает 80-байтовую meta
// (token‖sessionKey‖flowID), валидирует токен и отдаёт conn обработчику.
func acceptMetaLoop(ln net.Listener, secret []byte, tag string, handle func(conn net.Conn, sessionKey, flowID []byte)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		meta := make([]byte, 80)
		if _, err := io.ReadFull(conn, meta); err != nil {
			fmt.Printf("EIDOLON_QUIC_DIAG: %s meta read failed: %v\n", tag, err)
			conn.Close()
			continue
		}
		token := meta[:32]
		sessionKey := meta[32:64]
		flowID := meta[64:]
		if !ValidateTokenConstantTime(string(secret), token, nil) {
			fmt.Printf("EIDOLON_QUIC_DIAG: %s token validation FAILED -> closing\n", tag)
			conn.Close()
			continue
		}
		go handle(conn, sessionKey, flowID)
	}
}

func listenNative(ctx context.Context, host string, port int, secret []byte, onAccept func(net.Conn, []byte, []byte), onDatagram func(net.Conn, []byte), transport nativeTransport) error {
	localListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	go acceptMetaLoop(localListener, secret, "reliable",
		func(conn net.Conn, sessionKey, flowID []byte) { onAccept(conn, sessionKey, flowID) })

	// Фаза 4: для MoQT с датаграм-обработчиком поднимаем ВТОРОЙ локальный listener
	// (датаграм cb_port). Натив шлёт туда meta(80), затем кадрированные датаграммы.
	var datagramListener net.Listener
	var datagramPort int
	if transport == transportMoQT && onDatagram != nil {
		datagramListener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			localListener.Close()
			return err
		}
		datagramPort = datagramListener.Addr().(*net.TCPAddr).Port
		go acceptMetaLoop(datagramListener, secret, "datagram",
			func(conn net.Conn, sessionKey, _ []byte) { onDatagram(conn, sessionKey) })
	}

	localPort := localListener.Addr().(*net.TCPAddr).Port
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))
	cSecret := (*C.uint8_t)(unsafe.Pointer(&secret[0]))

	var handle C.EidolonHandle
	if transport == transportMoQT {
		handle = C.eidolon_listen_moqt(cHost, C.uint16_t(port), cSecret, C.size_t(len(secret)), C.uintptr_t(localPort), C.uintptr_t(datagramPort))
	} else {
		handle = C.eidolon_listen_quic(cHost, C.uint16_t(port), cSecret, C.size_t(len(secret)), C.uintptr_t(localPort))
	}
	if handle == nil {
		localListener.Close()
		if datagramListener != nil {
			datagramListener.Close()
		}
		return errors.New("failed to start native listener in C++")
	}
	registerActiveHandle(handle)

	go func() {
		<-ctx.Done()
		safeCloseHandle(handle)
		localListener.Close()
		if datagramListener != nil {
			datagramListener.Close()
		}
	}()

	return nil
}

// ExportKeyingMaterial запрашивает 32 байта ключа для TLS Exporter из C++
func (c *NativeStackConn) ExportKeyingMaterial() ([]byte, error) {
	if c == nil {
		return nil, errors.New("native stack: uninitialized or closed session handle")
	}
	c.closeMu.RLock()
	defer c.closeMu.RUnlock()

	if c.handle == nil || c.closed {
		return nil, errors.New("native stack: uninitialized or closed session handle")
	}
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
	if c == nil {
		return nil
	}
	c.closeMu.Lock()
	h := c.handle
	c.handle = nil
	c.closed = true
	dc := c.datagramConn
	c.closeMu.Unlock()

	var err error
	if c.dataConn != nil {
		err = c.dataConn.Close()
	}
	if dc != nil {
		dc.Close() // разблокирует ReadDatagram демукс-горутины
	}
	if h != nil {
		safeCloseHandle(h)
	}
	return err
}

func (c *NativeStackConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *NativeStackConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *NativeStackConn) SetDeadline(t time.Time) error      { return c.dataConn.SetDeadline(t) }
func (c *NativeStackConn) SetReadDeadline(t time.Time) error  { return c.dataConn.SetReadDeadline(t) }
func (c *NativeStackConn) SetWriteDeadline(t time.Time) error { return c.dataConn.SetWriteDeadline(t) }