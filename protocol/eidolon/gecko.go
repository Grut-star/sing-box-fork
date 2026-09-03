package eidolon

import (
	"crypto/rand"
	"net"
	"time"
)

// TODO: Чисто заметка. Т.К. перешли к Нативному стэку, то мы больше так не можем
// Разве что писать класс-обертку к net::TCPClientSocket
// Но в теории это может быть поведенченский паттерн

// GeckoConn дробит первые пакеты для обхода сигнатурного анализа DPI
type GeckoConn struct {
	net.Conn
	bytesWritten int
	maxGecko     int
}

func NewGeckoConn(conn net.Conn) net.Conn {
	return &GeckoConn{
		Conn:     conn,
		maxGecko: 2048, // Дробим только первые 2 КБ (этап хендшейка)
	}
}

func (c *GeckoConn) Write(b []byte) (int, error) {
	if c.bytesWritten >= c.maxGecko || len(b) < 32 {
		return c.Conn.Write(b)
	}

	totalLen := len(b)
	randByte := make([]byte, 1)
	rand.Read(randByte)

	// Дробим на 2-5 фрагментов
	fragments := 2 + int(randByte[0]%4)
	chunkSize := totalLen / fragments
	offset := 0

	for i := 0; i < fragments; i++ {
		end := offset + chunkSize
		if i == fragments-1 {
			end = totalLen
		}

		if _, err := c.Conn.Write(b[offset:end]); err != nil {
			return offset, err
		}
		offset = end

		// Микро-задержка (Jitter) от 1 до 4 мс ломает склейку пакетов на DPI
		jitter := time.Duration(1+int(randByte[0]%4)) * time.Millisecond
		time.Sleep(jitter)
	}

	c.bytesWritten += totalLen
	return totalLen, nil
}