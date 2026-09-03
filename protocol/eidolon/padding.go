package eidolon

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"io"
	"net"
)

const maxPaddings = 8 // Добавляем мусор только в первые 8 пакетов сессии

// PaddedConn оборачивает net.Conn и добавляет обфускацию длин
type PaddedConn struct {
	net.Conn
	writeCount int
	readBuf    []byte
}

// Write упаковывает данные в бинарный кадр: [Len Payload: 2][Len Padding: 2][Payload][Padding]
func (c *PaddedConn) Write(b []byte) (int, error) {
	payloadLen := len(b)
	padLen := 0

	// Генерируем от 16 до 64 байт случайного мусора для первых 8 пакетов
	if c.writeCount < maxPaddings {
		//padLen = 16 + (int(b[0]) % 48) // Псевдослучайная длина без тяжелой математики
		n, _ := rand.Int(rand.Reader, big.NewInt(48))
        padLen = 16 + int(n.Int64()) // Получаем случайную длину от 16 до 63 байт
		c.writeCount++
	}

	frame := make([]byte, 4+payloadLen+padLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint16(frame[2:4], uint16(padLen))

	copy(frame[4:4+payloadLen], b)
	if padLen > 0 {
		rand.Read(frame[4+payloadLen:]) // Заполняем конец случайными байтами
	}

	_, err := c.Conn.Write(frame)
	return payloadLen, err
}

func (c *PaddedConn) Read(b []byte) (int, error) {
	// Если у нас остались данные от предыдущего чтения, отдаем их
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Читаем 4 байта заголовка строго целиком
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}

	payloadLen := int(binary.BigEndian.Uint16(header[0:2]))
	padLen := int(binary.BigEndian.Uint16(header[2:4]))

	// Читаем полезную нагрузку
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}

	// Читаем и отбрасываем мусорный паддинг, если он есть
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(padLen)); err != nil {
			return 0, err
		}
	}

	// Копируем данные в буфер пользователя
	n := copy(b, payload)
	// Если буфер пользователя слишком мал, сохраняем остаток
	if n < payloadLen {
		c.readBuf = payload[n:]
	}

	return n, nil
}