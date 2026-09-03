package eidolon

import (
	"crypto/tls"
	"errors"
	utls "github.com/metacubex/utls"
)

const exporterLabel = "eidolon-traffic-key"

// DeriveSessionKey извлекает 32-байтный симметричный ключ из установленного TLS-сеанса.
// Если сессия была перехвачена (MITM), клиент и сервер получат разные ключи,
// и расшифровка внутреннего трафика не удастся.
// func DeriveSessionKey(conn interface{}) ([]byte, error) {
// 	var exportFunc func(label string, context []byte, length int) ([]byte, error)
//
// 	switch c := conn.(type) {
// 	case *tls.Conn:
// 		exportFunc = c.ExportKeyingMaterial
// 	case *utls.UConn:
// 		exportFunc = c.ExportKeyingMaterial
// 	default:
// 		return nil, errors.New("unsupported connection type for TLS Exporter")
// 	}
//
// 	// Генерируем 32 байта для AEAD-шифра (например, ChaCha20-Poly1305)
// 	return exportFunc(exporterLabel, nil, 32)
// }
func DeriveSessionKey(conn interface{}) ([]byte, error) {
	switch c := conn.(type) {
	case *tls.Conn:
		cs := c.ConnectionState()
		return cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	case *utls.UConn:
		cs := c.ConnectionState()
		return cs.ExportKeyingMaterial(exporterLabel, nil, 32)
	default:
		return nil, errors.New("unsupported connection type for TLS Exporter")
	}
}