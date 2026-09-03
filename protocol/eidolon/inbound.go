package eidolon

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"time"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"


	"github.com/sagernet/sing-box/protocol/eidolon/federation"
)
//sTls "github.com/sagernet/sing/common/tls"
var _ adapter.Inbound = (*Inbound)(nil)

type Inbound struct {
	ctx            context.Context
	router         adapter.Router
	logger         log.ContextLogger
	options        option.EidolonInboundOptions
	tag            string
	sessionManager *ServerSessionManager

	configMu sync.RWMutex // Защищает динамические параметры от Data Race
    activeSecret string
    activeDest   string

    syncer *federation.NodeSyncer // nil в режиме Standalone
}


func (i *Inbound) getSecretAndDest() (string, string) {
	i.configMu.RLock()
	defer i.configMu.RUnlock()
	return i.activeSecret, i.activeDest
}

func (i *Inbound) UpdateFederationState(secret, dest string) {
	i.configMu.Lock()
    defer i.configMu.Unlock()
    if secret != "" {
       i.activeSecret = secret

       // Опционально: синхронизируем новый секрет с локальным Caddy-плагином по петлевому интерфейсу
       go func(sec string) {
           req, _ := http.NewRequest("POST", "http://127.0.0.1:11223/_internal/update_secret", nil)
           req.Header.Set("X-New-Secret", sec)
           client := &http.Client{Timeout: 2 * time.Second}
           _, _ = client.Do(req)
       }(secret)
    }
    if dest != "" {
       i.activeDest = dest
    }
}

// func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EidolonInboundOptions) (adapter.Inbound, error) {
// 	i := &Inbound{
// 		ctx:     ctx,
// 		router:  router,
// 		logger:  logger,
// 		options: options,
// 		tag:     tag,
//
// 		activeSecret: options.MasterSecret,
//         activeDest:   options.Dest,
// 	}
// 	i.sessionManager = NewServerSessionManager(i)
//
// 	// Инициализация Federation-режима, если в конфиге указан OporaURL
//     if options.Federation != nil && options.Federation.Enabled {
//         syncer, err := federation.NewNodeSyncer(
//             options.Federation.OporaURL,
//             options.Federation.Token,
//             options.Federation.PubKey,
//             time.Minute*10, // Обновляемся раз в 10 минут
//             logger,
//             i.UpdateFederationState,
//         )
//         if err != nil {
//             return nil, err
//         }
//         i.syncer = syncer
//     }
//
// 	return i, nil
// }

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.EidolonInboundOptions) (adapter.Inbound, error) {
    // Жестко привязываем ядро к локальному интерфейсу
    //options.ListenOptions.Listen = "127.0.0.1"
    options.ListenOptions.ListenPort = 8443

    // Моно-сервер: возвращаем зонды на локальный HTTP-порт Caddy
    options.Dest = "127.0.0.1:8080"

    i := &Inbound{
        ctx:     ctx,
        router:  router,
        logger:  logger,
        options: options,
        tag:     tag,
        activeSecret: options.MasterSecret,
        activeDest:   options.Dest, // Теперь указывает на Caddy
    }
    i.sessionManager = NewServerSessionManager(i)
//Инициализация Federation-режима, если в конфиге указан OporaURL
    if options.Federation != nil && options.Federation.Enabled {
        syncer, err := federation.NewNodeSyncer(
            options.Federation.OporaURL,
            options.Federation.Token,
            options.Federation.PubKey,
            time.Minute*10, // Обновляемся раз в 10 минут
            logger,
            i.UpdateFederationState,
        )
        if err != nil {
            return nil, err
        }
        i.syncer = syncer
    }

    return i, nil
}

func (i *Inbound) Type() string { return "eidolon" }
func (i *Inbound) Tag() string  { return i.tag }
func (i *Inbound) Start(stage adapter.StartStage) error {
    if i.syncer != nil {
		i.syncer.Start()
		i.logger.Info("Starting in FEDERATION mode. Node is managed by Opora.")
	} else {
		i.logger.Info("Starting in STANDALONE mode.")
	}
	return nil
}
func (i *Inbound) Close() error { return nil }

type PeekedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *PeekedConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func (i *Inbound) HandleTCPConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	// ПОЛУЧАЕМ АКТУАЛЬНЫЕ ДАННЫЕ
	secret, dest := i.getSecretAndDest()

	reader := bufio.NewReader(conn)
	peekBytes, err := reader.Peek(1024)
	isAuthorized := false

	if err == nil && len(peekBytes) >= 76 && peekBytes[0] == 0x16 && peekBytes[1] == 0x03 {
		sessionIDLenOffset := 43
		if sessionIDLenOffset < len(peekBytes) {
			sessionIDLen := int(peekBytes[sessionIDLenOffset])
			sessionIDStart := sessionIDLenOffset + 1

			if sessionIDLen == 32 && sessionIDStart+32 <= len(peekBytes) {
				sessionID := peekBytes[sessionIDStart : sessionIDStart+32]
				keyShare := extractKeyShare(peekBytes[sessionIDStart+32:])
                // ИСПОЛЬЗУЕМ ДИНАМИЧЕСКИЙ secret
				if ValidateTokenConstantTime(secret, sessionID, keyShare) {
					isAuthorized = true
				}
			}
		}
	}

	wrappedConn := &PeekedConn{Conn: conn, Reader: reader}

	if !isAuthorized {
// 		i.logger.Warn("Active probe detected. Executing Zero-Delay Fallback to: ", i.options.Dest)
// 		return i.fallbackToDest(wrappedConn)
       // ИСПОЛЬЗУЕМ ДИНАМИЧЕСКИЙ dest
       i.logger.Warn("Active probe detected. Executing Zero-Delay Fallback to: ", dest)
       return i.fallbackToDest(wrappedConn, dest) // Передаем dest аргументом!
	}

	i.logger.Info("Eidolon Client Authorized. Terminating TLS and assembling pipeline.")

	tlsConfig, err := i.getTLSConfig()
	if err != nil {
		return err
	}

	tlsConn := tls.Server(wrappedConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}

	sessionKey, err := DeriveSessionKey(tlsConn)
	if err != nil {
		return err
	}

	flowID := make([]byte, 16)
	if _, err := io.ReadFull(tlsConn, flowID); err != nil {
		return err
	}

	// Восстанавливаем защиту длин пакетов на сервере
	paddedConn := &PaddedConn{Conn: tlsConn}

	// ВНЕДРЕНИЕ: Оборачиваем соединение в шейпер на стороне сервера (Downlink)
    // Теперь исходящий от сервера к клиенту трафик будет группироваться в DASH-чанки
    shaperConn := NewBurstShaperConn(paddedConn)

    // Передаем защищенный и сформированный сокет в Менеджер Сессий
	i.sessionManager.RegisterTCP(flowID, shaperConn, sessionKey)
	return nil
}

func extractKeyShare(raw []byte) []byte {
	// Мы просто используем входящий слайс raw напрямую
	for idx := 0; idx < len(raw)-4; idx++ {
		if raw[idx] == 0x00 && raw[idx+1] == 0x33 {
			extLen := int(binary.BigEndian.Uint16(raw[idx+2 : idx+4]))
			if idx+4+extLen <= len(raw) {
				extData := raw[idx+4 : idx+4+extLen]
				if len(extData) >= 6 {
					keyLen := int(binary.BigEndian.Uint16(extData[4:6]))
					if 6+keyLen <= len(extData) {
						return extData[6 : 6+keyLen]
					}
				}
			}
		}
	}
	return nil
}

func (i *Inbound) fallbackToDest(clientConn net.Conn, dest string) error {
	defer clientConn.Close()
	// Подключаемся к актуальному сайту-донору
    destConn, err := net.Dial("tcp", dest)

	if err != nil {
		return err
	}
	defer destConn.Close()

	errc := make(chan error, 2)
	go func() { _, err := io.Copy(destConn, clientConn); errc <- err }()
	go func() { _, err := io.Copy(clientConn, destConn); errc <- err }()
	<-errc
	return nil
}

// getTLSConfig нативно компилирует TLS-конфигурацию через ядро sing-box.
// Он автоматически поддерживает как Standalone (классические сертификаты),
// так и REALITY (на основе X25519 PrivateKey), опираясь на JSON-конфиг.
func (i *Inbound) getTLSConfig() (*tls.Config, error) {
	if i.options.TLS == nil {
		return nil, errors.New("eidolon: TLS options are missing in configuration")
	}

	// sTls.NewServer создает готовый интерфейс Server (обертка sing-box)
// 	serverTLS, err := sTls.NewServer(i.ctx, sTls.ServerOptions{
// 		Context:    i.ctx,
// 		Options:    *i.options.TLS,
// 		DefaultALPN: []string{"h3", "h2", "http/1.1"},
// 	})

// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Извлекаем стандартный *tls.Config (для Standalone) или
// 	// специальный *tls.Config с хуками GetConfigForClient (для REALITY)
// 	config, err := serverTLS.Config()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Для QUIC (UDP) обязательно требуется поддержка ALPN HTTP/3
// 	config.NextProtos = []string{"h3"}
    config := &tls.Config{
        NextProtos: []string{"h3", "h2", "http/1.1"},
    }

	return config, nil
}
