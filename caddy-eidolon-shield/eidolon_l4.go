package eidolon_l4

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(EidolonL4{})
}

type EidolonL4 struct {
	ProxyDomain  string `json:"proxy_domain,omitempty"`
	CoreAddr     string `json:"core_addr,omitempty"`     // TCP ядро (например, 127.0.0.1:8443)
	UDPCoreAddr  string `json:"udp_core_addr,omitempty"` // UDP ядро (например, 127.0.0.1:8443)
	UDPListen    string `json:"udp_listen,omitempty"`    // Внешний UDP (например, 0.0.0.0:443)

	udpListener  *net.UDPConn
	udpCloseChan chan struct{}
	wg           sync.WaitGroup
}

func (EidolonL4) CaddyModuleInfo() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.eidolon_l4",
		New: func() caddy.Module { return new(EidolonL4) },
	}
}

// Provision запускает UDP Blind Proxy при инициализации модуля
func (e *EidolonL4) Provision(ctx caddy.Context) error {
	if e.UDPListen == "" || e.UDPCoreAddr == "" {
		return nil // UDP прокси отключен, если не заданы адреса
	}

	listenAddr, err := net.ResolveUDPAddr("udp", e.UDPListen)
	if err != nil {
		return err
	}
	coreAddr, err := net.ResolveUDPAddr("udp", e.UDPCoreAddr)
	if err != nil {
		return err
	}

	e.udpListener, err = net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}

	e.udpCloseChan = make(chan struct{})
	e.wg.Add(1)

	go e.runUDPProxy(coreAddr)
	return nil
}


// Cleanup корректно завершает работу UDP-сокета при перезагрузке Caddy
func (e *EidolonL4) Cleanup() error {
	if e.udpCloseChan != nil {
		close(e.udpCloseChan)
	}
	if e.udpListener != nil {
		e.udpListener.Close()
	}
	e.wg.Wait()
	return nil
}

func (e *EidolonL4) runUDPProxy(coreAddr *net.UDPAddr) {
	defer e.wg.Done()
	buf := make([]byte, 65535)

	for {
		n, clientAddr, err := e.udpListener.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-e.udpCloseChan:
				return
			default:
				continue
			}
		}

		coreConn, err := net.DialUDP("udp", nil, coreAddr)
		if err != nil {
			continue
		}

		coreConn.Write(buf[:n])

		go func(c *net.UDPConn, cAddr *net.UDPAddr) {
			defer c.Close()
			resp := make([]byte, 65535)
			rn, _, err := c.ReadFromUDP(resp)
			if err == nil {
				e.udpListener.WriteToUDP(resp[:rn], cAddr)
			}
		}(coreConn, clientAddr)
	}
}

func (e *EidolonL4) WrapListener(l net.Listener) net.Listener {
	return &sniListener{Listener: l, config: e}
}

type sniListener struct {
	net.Listener
	config *EidolonL4
}

func (l *sniListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Читаем достаточно байт для захвата ClientHello (обычно до 2-3 КБ)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return &bufferedConn{Conn: conn, buf: buf[:n]}, nil
	}

	sni := extractSNI(buf[:n])

	// Точное совпадение SNI — прозрачный бинарный проброс в ядро
	if sni == l.config.ProxyDomain {
		coreConn, err := net.Dial("tcp", l.config.CoreAddr)
		if err == nil {
			go io.Copy(coreConn, io.MultiReader(bytes.NewReader(buf[:n]), conn))
			go func() {
				io.Copy(conn, coreConn)
				conn.Close()
			}()
			return l.Accept()
		}
	}

	// Возвращаем сокет в пайплайн Caddy
	return &bufferedConn{Conn: conn, buf: buf[:n]}, nil
}

// Строгий бинарный парсинг TLS ClientHello для извлечения SNI
func extractSNI(data []byte) string {
	if len(data) < 43 || data[0] != 0x16 { // 0x16 = Handshake
		return ""
	}

	sessionIDLen := int(data[43])
	if 44+sessionIDLen+2 > len(data) {
		return ""
	}

	cipherLen := int(binary.BigEndian.Uint16(data[44+sessionIDLen : 46+sessionIDLen]))
	compOffset := 46 + sessionIDLen + cipherLen
	if compOffset+1 > len(data) {
		return ""
	}

	compLen := int(data[compOffset])
	extOffset := compOffset + 1 + compLen
	if extOffset+2 > len(data) {
		return ""
	}

	extLen := int(binary.BigEndian.Uint16(data[extOffset : extOffset+2]))
	exts := data[extOffset+2:]
	if len(exts) < extLen {
		return ""
	}

	for i := 0; i < extLen; {
		if i+4 > len(exts) {
			break
		}
		extType := binary.BigEndian.Uint16(exts[i : i+2])
		extLength := int(binary.BigEndian.Uint16(exts[i+2 : i+4]))
		i += 4

		if extType == 0x00 && extLength > 5 { // Server Name Extension
			nameLen := int(binary.BigEndian.Uint16(exts[i+3 : i+5]))
			if i+5+nameLen <= len(exts) {
				return string(exts[i+5 : i+5+nameLen])
			}
		}
		i += extLength
	}
	return ""
}

type bufferedConn struct {
	net.Conn
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}