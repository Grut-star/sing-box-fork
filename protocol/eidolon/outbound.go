package eidolon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/smux"
)

var _ adapter.Outbound = (*Outbound)(nil)
var lastLogTime int64

type Outbound struct {
	ctx       context.Context
	router    adapter.Router
	logger    log.ContextLogger
	options   option.EidolonOutboundOptions
	tag       string

	sessionMu sync.Mutex
	session   *SessionPool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EidolonOutboundOptions) (adapter.Outbound, error) {
// 	if options.Concurrency <= 0 {
// 		options.Concurrency = 3 // По умолчанию 3 потока, как у легитимных браузеров
// 	}
	return &Outbound{ctx: ctx, router: router, logger: logger, options: options, tag: tag}, nil
}

func (o *Outbound) Type() string           { return "eidolon" }
func (o *Outbound) Tag() string            { return o.tag }
func (o *Outbound) Network() []string      { return []string{"tcp", "udp"} }
func (o *Outbound) Dependencies() []string { return nil }

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	session, err := o.GetOrCreateSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.GetStream(ctx)
	if err != nil {
		return nil, err
	}

	// Отправляем заголовок назначения (0x00 - TCP)
	if err := writeDestination(stream, destination, false); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	session, err := o.GetOrCreateSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.GetStream(ctx)
	if err != nil {
		return nil, err
	}

	// Отправляем заголовок назначения (0x01 - UDP)
	if err := writeDestination(stream, destination, true); err != nil {
		stream.Close()
		return nil, err
	}

	// Оборачиваем надежный стрим в интерфейс PacketConn (UDP-over-TCP)
	return EncapsulateUDPoverStream(stream), nil
}

func (o *Outbound) GetOrCreateSession(ctx context.Context) (*SessionPool, error) {
	o.sessionMu.Lock()
	defer o.sessionMu.Unlock()

	if o.session != nil {
		o.session.CheckAndHeal(ctx) // Триггер фонового восстановления
		if o.session.IsHealthy() {
			return o.session, nil
		}
	}
    concurrencyLimit := 3 // Жестко задаем размер пула (как у легитимных браузеров)

    o.logger.Info(fmt.Sprintf("Initializing SessionPool pool (Concurrency: %d)", concurrencyLimit))
    session := &SessionPool{
        flowID:      GenerateFlowID(),
        logger:      o.logger,
        concurrency: concurrencyLimit,
        outbound:    o,
    }

    // Синхронно прогреваем пул при первом запуске
    session.replenishPool(ctx, concurrencyLimit)

	if !session.IsHealthy() {
		return nil, errors.New("eidolon: failed to establish transport connections")
	}

	o.session = session
	return session, nil
}

// =========================================================================
// HYBRID SESSION (AUTO-HEALING POOL)
// =========================================================================

// type HybridSession struct {
// 	flowID      []byte
// 	logger      log.ContextLogger
// 	concurrency int
// 	outbound    *Outbound
//
// 	mu       sync.RWMutex
// 	tcpPool  []*smux.Session
// 	quicPool []quic.Connection
// 	rrIndex  uint32
// 	isDialing int32 // Атомарный флаг блокировки фонового дозвона
// }

// SessionPool управляет массивом активных соединений и авто-восстановлением
type SessionPool struct {
	flowID      []byte
	logger      log.ContextLogger
	concurrency int
	outbound    *Outbound

	mu       sync.RWMutex
	tcpPool  []*smux.Session
	quicPool  []*smux.Session
	rrIndex  uint32
	isDialing int32 // Атомарный флаг блокировки фонового дозвона
}

// dialLane выполняет дозвон и безопасно добавляет соединение в пул (Concurrency Safe)
func (o *Outbound) dialLane(ctx context.Context, pool *SessionPool, isQUIC bool) {
    var rawConn net.Conn
	var sessionKey []byte
	var err error

	if isQUIC {
		rawConn, sessionKey, err = o.DialQUIC(ctx, pool.flowID)
		if err != nil {
			o.logger.Warn("QUIC lane dial failed: ", err)
			return
		}
	} else {
		rawConn, sessionKey, err = o.DialTCP(ctx, pool.flowID)
		if err != nil {
			o.logger.Warn("TCP lane dial failed: ", err)
			return
		}
	}

	// БЕСКОМПРОМИССНАЯ БЕЗОПАСНОСТЬ: И TCP, и QUIC теперь надежные потоки Chromium.
	// Оборачиваем их в AEAD и smux.
	secureConn, err := NewAEADStreamConn(rawConn, sessionKey, true) // isClient = true
	if err != nil {
		rawConn.Close()
		o.logger.Error("AEAD derivation failed for lane: ", err)
		return
	}

	mux, err := smux.Client(secureConn, smux.DefaultConfig())
	if err != nil {
		secureConn.Close()
		o.logger.Error("smux Client initialization failed: ", err)
		return
	}

	pool.mu.Lock()
	if isQUIC {
		pool.quicPool = append(pool.quicPool, mux)
	} else {
		pool.tcpPool = append(pool.tcpPool, mux)
	}
	pool.mu.Unlock()
}

// CheckAndHeal очищает мертвые соединения и фоном восполняет пул
func (s *SessionPool) CheckAndHeal(ctx context.Context) {
	s.mu.Lock()

	// Очистка TCP
	var activeTCP []*smux.Session
	for _, m := range s.tcpPool {
		if !m.IsClosed() {
			activeTCP = append(activeTCP, m)
		}
	}
	s.tcpPool = activeTCP

	// Очистка QUIC (проверка закрытия контекста)
	var activeQUIC []*smux.Session
    for _, m := range s.quicPool {
        if !m.IsClosed() {
            activeQUIC = append(activeQUIC, m)
        }
    }
    s.quicPool = activeQUIC

	alive := len(s.tcpPool) + len(s.quicPool)
	shortfall := s.concurrency - alive
	s.mu.Unlock()

	// Если пул деградировал, запускаем фоновый воркер
	if shortfall > 0 && atomic.CompareAndSwapInt32(&s.isDialing, 0, 1) {
        go func() {
            defer atomic.StoreInt32(&s.isDialing, 0)
            s.logger.Warn(fmt.Sprintf("Pool degraded. Auto-healing %d connections in background", shortfall))
            s.replenishPool(context.Background(), shortfall)
        }()
    }
}

func (s *SessionPool) replenishPool(ctx context.Context, count int) {
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.outbound.dialLane(ctx, s, false) // TCP Lane
		}()
		go func() {
			defer wg.Done()
			s.outbound.dialLane(ctx, s, true)  // QUIC Lane
		}()
	}
	wg.Wait()
}

func (s *SessionPool) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tcpPool) > 0 || len(s.quicPool) > 0
}

// GetStream прозрачно балансирует запросы между TCP(smux) и QUIC(native)
func (s *SessionPool) GetStream(ctx context.Context) (net.Conn, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    tcpLen := uint32(len(s.tcpPool))
    quicLen := uint32(len(s.quicPool))
    total := tcpLen + quicLen

    if total == 0 {
        return nil, errors.New("eidolon: pool is empty")
    }

    idx := atomic.AddUint32(&s.rrIndex, 1) % total

    var mux *smux.Session
    if idx < quicLen {
        mux = s.quicPool[idx]
    } else {
        mux = s.tcpPool[idx-quicLen]
    }

    if mux.NumStreams() >= 2048 {
        return nil, errors.New("smux stream limit reached")
    }

    stream, err := mux.OpenStream()
    if err != nil {
        return nil, err // Returns a true untyped nil interface
    }
    return stream, nil
}

func (o *Outbound) DialTCP(ctx context.Context, flowID []byte) (net.Conn, []byte, error) {
	token := GenerateToken(o.options.MasterSecret, 0, nil)
	nativeConn, err := DialNativeTCP(ctx, o.options.Server, int(o.options.ServerPort), token)
	if err != nil {
		return nil, nil, err
	}
	if _, err := nativeConn.Write(flowID); err != nil {
		nativeConn.Close()
		return nil, nil, err
	}
	sessionKey, err := nativeConn.ExportKeyingMaterial()
	if err != nil {
		nativeConn.Close()
		return nil, nil, err
	}
	o.logger.Info("Eidolon Native Chromium TCP Transport established.")
	paddedConn := &PaddedConn{Conn: nativeConn}
	return paddedConn, sessionKey, nil
}

func (o *Outbound) DialQUIC(ctx context.Context, flowID []byte) (net.Conn, []byte, error) {
	token := GenerateToken(o.options.MasterSecret, 0, nil)
	nativeConn, err := DialNativeQUIC(ctx, o.options.Server, int(o.options.ServerPort), token)
	if err != nil {
		return nil, nil, err
	}

	// C++ мост устанавливает HTTP/3 стрим. Отправляем FlowID в этот стрим.
	if _, err := nativeConn.Write(flowID); err != nil {
		nativeConn.Close()
		return nil, nil, err
	}
	sessionKey, err := nativeConn.ExportKeyingMaterial()
	if err != nil {
		nativeConn.Close()
		return nil, nil, err
	}
	o.logger.Info("Eidolon Native Chromium QUIC Transport established.")
	paddedConn := &PaddedConn{Conn: nativeConn}
	return paddedConn, sessionKey, nil
}