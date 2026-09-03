package eidolon

import (
	"net"
	"github.com/sagernet/smux"
)

func (i *Inbound) StartQUICListener() error {
	addr := "127.0.0.1"
	port := int(i.options.ListenOptions.ListenPort)
	i.logger.Info("Starting Native Chromium QUIC Listener on ", addr, ":", port)

	err := ListenNativeQUIC(i.ctx, addr, port, []byte(i.options.MasterSecret), func(conn net.Conn, sessionKey []byte, flowID []byte) {
		secureQUIC, err := NewAEADStreamConn(conn, sessionKey, false)
		if err != nil {
			i.logger.Error("AEAD QUIC derivation failed: ", err)
			conn.Close()
			return
		}
		quicMux, err := smux.Server(secureQUIC, smux.DefaultConfig())
		if err != nil {
			i.logger.Error("smux Server initialization failed: ", err)
			conn.Close()
			return
		}
		i.sessionManager.RegisterQUIC(flowID, quicMux)
	})
	return err
}