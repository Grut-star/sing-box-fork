package eidolon

import (
    "encoding/binary"
    "encoding/hex"
	"sync"
	"time"
	"io"
    "net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

// ServerSessionManager управляет жизненным циклом гибридных сессий.
type ServerSessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*ServerSession
	inbound  *Inbound
}

func NewServerSessionManager(inbound *Inbound) *ServerSessionManager {
	return &ServerSessionManager{
		sessions: make(map[string]*ServerSession),
		inbound:  inbound,
	}
}

// ServerSession описывает состояние гибридной сессии клиента.
type ServerSession struct {
	flowID string
	mgr    *ServerSessionManager

	mu       sync.RWMutex
	tcpRaw   net.Conn
	tcpKey   []byte

	quicMux  *smux.Session

	tcpArrived  chan struct{}
	quicArrived chan struct{}

	// Флаги состояния маршрутизации (чтобы не запустить транспорт дважды)
	tcpRouted           bool
	quicRouted          bool
	pairingWindowClosed bool

	startOnce sync.Once
}

// RegisterTCP регистрирует входящее TCP-соединение
func (m *ServerSessionManager) RegisterTCP(flowID []byte, conn net.Conn, key []byte) {
	sess := m.getOrCreateSession(flowID)

	sess.mu.Lock()
	sess.tcpRaw = conn
	sess.tcpKey = key
	select {
	case <-sess.tcpArrived:
	default:
		close(sess.tcpArrived)
	}
	windowClosed := sess.pairingWindowClosed
	sess.mu.Unlock()

	m.inbound.logger.Info("TCP transport attached to session. FlowID: ", sess.flowID)

	// Hot-Plugging: Если окно спаривания уже закрыто, стартуем TCP немедленно
	if windowClosed {
		sess.tryRouteTCP()
	}
}

// RegisterQUIC регистрирует входящее QUIC-соединение (асинхронный UDP)
func (m *ServerSessionManager) RegisterQUIC(flowID []byte, mux *smux.Session) {
	sess := m.getOrCreateSession(flowID)
	sess.mu.Lock()
	sess.quicMux = mux
	select {
	case <-sess.quicArrived:
	default:
		close(sess.quicArrived)
	}
	windowClosed := sess.pairingWindowClosed
	sess.mu.Unlock()

	m.inbound.logger.Info("QUIC smux transport attached to session. FlowID: ", sess.flowID)
	if windowClosed {
		sess.tryRouteQUIC()
	}
}

func (m *ServerSessionManager) getOrCreateSession(flowID []byte) *ServerSession {
	id := hex.EncodeToString(flowID)

	m.mu.Lock()
	defer m.mu.Unlock()

	sess, exists := m.sessions[id]
	if !exists {
		sess = &ServerSession{
			flowID:      id,
			mgr:         m,
			tcpArrived:  make(chan struct{}),
			quicArrived: make(chan struct{}),
		}
		m.sessions[id] = sess

		go sess.startPairingLifecycle()
	}

	return sess
}

// startPairingLifecycle ждет до 1.5 секунд для синхронного запуска обоих транспортов
func (s *ServerSession) startPairingLifecycle() {
	s.startOnce.Do(func() {
		pairingTimeout := time.After(1500 * time.Millisecond)
		tcpReady, quicReady := false, false

		for !tcpReady || !quicReady {
			select {
			case <-s.tcpArrived:
				tcpReady = true
			case <-s.quicArrived:
				quicReady = true
			case <-pairingTimeout:
				goto EvaluateState
			}
		}

	EvaluateState:
		s.mu.Lock()
		s.pairingWindowClosed = true
		hasTCP := s.tcpRaw != nil
		hasQUIC := s.quicMux != nil
		s.mu.Unlock()

		if hasTCP && hasQUIC {
			s.mgr.inbound.logger.Info("Perfect pairing achieved. FlowID: ", s.flowID)
		} else if hasTCP {
			s.mgr.inbound.logger.Warn("Pairing timeout: Operating in TCP-only degraded mode. FlowID: ", s.flowID)
		} else if hasQUIC {
			s.mgr.inbound.logger.Warn("Pairing timeout: Operating in QUIC-only degraded mode. FlowID: ", s.flowID)
		}

		// Запускаем маршрутизацию для тех транспортов, которые успели прибыть
		s.tryRouteTCP()
		s.tryRouteQUIC()
	})
}

// tryRouteTCP оборачивает TCP в AEAD + smux и отдает ядру sing-box
func (s *ServerSession) tryRouteTCP() {
	s.mu.Lock()
	if s.tcpRaw == nil || s.tcpRouted {
		s.mu.Unlock()
		return
	}
	s.tcpRouted = true
	conn := s.tcpRaw
	key := s.tcpKey
	s.mu.Unlock()

	secureTCP, err := NewAEADStreamConn(conn, key, false) // isClient = false
	if err != nil {
		s.mgr.inbound.logger.Error("AEAD TCP derivation failed: ", err)
		return
	}

	tcpMux, err := smux.Server(secureTCP, smux.DefaultConfig())
	if err != nil {
		s.mgr.inbound.logger.Error("smux Server initialization failed: ", err)
		return
	}

	go s.acceptStreams(tcpMux)
}

// tryRouteQUIC запускает обработку нативных QUIC-потоков
func (s *ServerSession) tryRouteQUIC() {
	s.mu.Lock()
	if s.quicMux == nil || s.quicRouted {
		s.mu.Unlock()
		return
	}
	s.quicRouted = true
	mux := s.quicMux
	s.mu.Unlock()

	go s.acceptStreams(mux)
}

func (s *ServerSession) acceptStreams(mux *smux.Session) {
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			break
		}
		go s.handleStream(stream)
	}
}

// acceptTCPStreams обрабатывает входящие потоки из smux
// func (s *ServerSession) acceptTCPStreams(mux *smux.Session) {
// 	for {
// 		stream, err := mux.AcceptStream()
// 		if err != nil {
// 			break
// 		}
// 		go s.handleStream(stream)
// 	}
// }

// acceptQUICStreams обрабатывает нативные входящие потоки QUIC
// func (s *ServerSession) acceptQUICStreams() {
// 	for {
// 		stream, err := s.quicConn.AcceptStream(s.mgr.inbound.ctx)
// 		if err != nil {
// 			break
// 		}
// 		// Обертка для net.Conn
// 		wrapped := &quicStreamWrapper{Stream: stream, qConn: s.quicConn}
// 		go s.handleStream(wrapped)
// 	}
// }

// handleStream читает заголовок и передает трафик в ядро sing-box
func (s *ServerSession) handleStream(stream net.Conn) {
	// 1. Читаем заголовок: [1 байт Флаг] + [2 байта Длина]
	header := make([]byte, 3)
	if _, err := io.ReadFull(stream, header); err != nil {
		stream.Close()
		return
	}

	isUDP := header[0] == 0x01
	addrLen := binary.BigEndian.Uint16(header[1:3])

	// 2. Читаем адрес назначения
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		stream.Close()
		return
	}

	destAddr := M.ParseSocksaddr(string(addrBuf))

	// 3. Формируем контекст для маршрутизатора
	metadata := adapter.InboundContext{
		Inbound:     s.mgr.inbound.tag,
		InboundType: s.mgr.inbound.Type(),
		Destination: destAddr,
	}

	// 4. Передаем в ядро
	if isUDP {
		metadata.Network = "udp"
		// Восстанавливаем границы UDP-пакетов поверх стрима
		packetConn := EncapsulateUDPoverStream(stream)

        // Оборачиваем стандартный net.PacketConn в формат sing-box (network.PacketConn)
        singPacketConn := bufio.NewPacketConn(packetConn)
		s.mgr.inbound.router.RoutePacketConnectionEx(s.mgr.inbound.ctx, singPacketConn, metadata, nil)
        // Передаем напрямую в роутер (Sing-box RoutePacketConnectionEx принимает стандартный net.PacketConn)
	} else {
		metadata.Network = "tcp"
		s.mgr.inbound.router.RouteConnectionEx(s.mgr.inbound.ctx, stream, metadata, nil)
	}
}