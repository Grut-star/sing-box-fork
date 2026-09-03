package eidolon

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/smux"
)
// UoTPacketConn оборачивает TCP-сокет, превращая его в net.PacketConn.
// Формат кадра: [2 байта длины (BigEndian)] + [Полезная нагрузка]
// type UoTPacketConn struct {
// 	net.Conn
// }

// HybridSession управляет связкой TCP и QUIC для одного клиента.
type HybridSession struct {
	mu       sync.RWMutex
	flowID   []byte
	tcpConn     net.Conn //храним сырой сокет для корректного Close()

	// Храним мультиплексоры, а не сырые коннекты
    tcpMux      *smux.Session
    quicMux     *smux.Session

	// Флаг деградации. Если что-то режет мы переходим на другой (Fallback)
    tcpDegraded bool // TCP заблокирован, гоним всё через QUIC Streams
    udpDegraded bool // UDP заблокирован, гоним всё через TCP (smux + UoT)

	logger      log.ContextLogger
}

func NewHybridSession(flowID []byte, logger log.ContextLogger) *HybridSession {
	return &HybridSession{
		flowID: flowID,
		logger: logger,
	}
}

// AttachTCP привязывает установленный TCP-канал к сессии
func (s *HybridSession) AttachTCP(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpConn = conn
}

// AttachQUIC привязывает установленный QUIC-канал к сессии
func (s *HybridSession) AttachQUIC(mux *smux.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quicMux = mux
	s.udpDegraded = false // Сбрасываем флаг деградации, так как QUIC ожил
}

// GetTCPChannel возвращает канал для нативного TCP-трафика
func (s *HybridSession) GetTCPChannel(ctx context.Context) (net.Conn, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Идеальный сценарий: TCP жив. Открываем новый логический стрим внутри smux.
	if s.tcpMux != nil && !s.tcpDegraded {
        stream, err := s.tcpMux.OpenStream()
        if err != nil {
            return nil, err
        }
        return stream, nil
    }

	// 2. Fallback: TCP заблокирован, но QUIC жив.
	// Открываем надежный двунаправленный поток внутри QUIC (работает как TCP).
	if s.quicMux != nil {
        s.logger.Warn("TCP degraded. Routing TCP connection over QUIC Stream.")
        stream, err := s.quicMux.OpenStream()
        if err != nil {
            return nil, err
        }
        return stream, nil
    }

	return nil, net.ErrClosed
}

// GetUDPChannel возвращает канал для нативного UDP-трафика.
// Если QUIC (UDP) заблокирован провайдером или просто не работает , плавно деградирует до UDP-over-TCP.
func (s *HybridSession) GetUDPChannel() (net.PacketConn, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Идеальный сценарий: QUIC жив. Открываем надёжный стрим.
	if s.quicMux != nil && !s.udpDegraded {
		stream, err := s.quicMux.OpenStream()
        if err != nil {
            return nil, err
        }
        // Фреймим UDP-пакеты (длина + payload), так как стрим склеивает байты
        return EncapsulateUDPoverStream(stream), nil
	}

	// 2. Fallback: UDP/QUIC заблокирован. Гоним UDP поверх TCP.
	if s.tcpMux != nil {
		s.logger.Warn("UDP degraded. Routing UDP over TCP (UoT) via smux.")
		stream, err := s.tcpMux.OpenStream()
		if err != nil {
			return nil, err
		}
		return EncapsulateUDPoverStream(stream), nil // Возвращаем наш UoT-адаптер
	}

	return nil, net.ErrClosed
}

// MarkUDPDegraded вызывается, если детектируется троттлинг или дроп QUIC пакетов
func (s *HybridSession) MarkUDPDegraded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpDegraded = true
	s.logger.Warn("QUIC transport marked as degraded. Shifting load to TCP.")
}

// Close закрывает оба плеча гибридной сессии
func (s *HybridSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errTCP, errQUIC error
	if s.tcpConn != nil {
		errTCP = s.tcpConn.Close()
	}
	if s.quicMux != nil {
		errQUIC = s.quicMux.Close()
	}

	if errTCP != nil {
		return errTCP
	}
	return errQUIC
}

// // encapsulateUDPoverTCP оборачивает TCP-канал для передачи UDP-трафика
// func encapsulateUDPoverTCP(tcpConn net.Conn) net.PacketConn {
// 	return &UoTPacketConn{Conn: tcpConn}
// }
//
// func (c *UoTPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
// 	// 1. Читаем 2 байта длины
// 	var length uint16
// 	err = binary.Read(c.Conn, binary.BigEndian, &length)
// 	if err != nil {
// 		return 0, nil, err
// 	}
//
// 	if int(length) > len(p) {
// 		return 0, nil, errors.New("UoT: incoming packet exceeds buffer size")
// 	}
//
// 	// 2. Читаем полезную нагрузку целиком
// 	n, err = io.ReadFull(c.Conn, p[:length])
//
// 	// В UoT удаленным адресом считается адрес TCP-пира
// 	return n, c.Conn.RemoteAddr(), err
// }
//
// func (c *UoTPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
// 	if len(p) > 65535 {
// 		return 0, errors.New("UoT: packet too large for 2-byte prefix")
// 	}
//
// 	// Аллоцируем буфер для кадра: 2 байта + Payload
// 	buf := make([]byte, 2+len(p))
// 	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
// 	copy(buf[2:], p)
//
// 	// Пишем кадр в TCP-поток
// 	_, err = c.Conn.Write(buf)
// 	return len(p), err
// }