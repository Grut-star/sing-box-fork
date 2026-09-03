package eidolon

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
    "math/big"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	maxPayloadSize = 0x3FFF // Максимальный размер блока (16KB - 1)
	nonceSize      = chacha20poly1305.NonceSize // 12 байт
	tagSize        = chacha20poly1305.Overhead  // 16 байт (Poly1305 MAC)
)

// DeriveAEADKeys использует HKDF для генерации независимых ключей чтения и записи.
// Параметр isClient определяет, какие ключи пойдут на Read, а какие на Write.
func DeriveAEADKeys(masterSessionKey []byte, isClient bool) (readAEAD, writeAEAD cipher.AEAD, err error) {
	// HKDF-генератор. Используем SHA256. Salt можно не передавать (nil),
	// так как мастер-ключ уже является криптографически сильным псевдослучайным материалом.
	hkdfReader := hkdf.New(sha256.New, masterSessionKey, nil, []byte("eidolon-inner-aead"))

	clientToServerKey := make([]byte, 32)
	serverToClientKey := make([]byte, 32)

	if _, err := io.ReadFull(hkdfReader, clientToServerKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdfReader, serverToClientKey); err != nil {
		return nil, nil, err
	}

	var readKey, writeKey []byte
	if isClient {
		writeKey = clientToServerKey
		readKey = serverToClientKey
	} else {
		writeKey = serverToClientKey
		readKey = clientToServerKey
	}

	readAEAD, err = chacha20poly1305.New(readKey)
	if err != nil {
		return nil, nil, err
	}

	writeAEAD, err = chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, nil, err
	}

	return readAEAD, writeAEAD, nil
}

// =========================================================================
// AEAD ОБЕРТКА ДЛЯ TCP (СТРОГАЯ ПОСЛЕДОВАТЕЛЬНОСТЬ, СЧЕТЧИК NONCE)
// =========================================================================

type AEADStreamConn struct {
	net.Conn
	readAEAD     cipher.AEAD
	writeAEAD    cipher.AEAD
	readCounter  uint64
	writeCounter uint64
	readBuf      []byte // Буфер для остатков расшифрованных данных
}

func NewAEADStreamConn(conn net.Conn, masterSessionKey []byte, isClient bool) (net.Conn, error) {
	rAEAD, wAEAD, err := DeriveAEADKeys(masterSessionKey, isClient)
	if err != nil {
		return nil, err
	}
	return &AEADStreamConn{
		Conn:      conn,
		readAEAD:  rAEAD,
		writeAEAD: wAEAD,
	}, nil
}

// makeNonce генерирует 12-байтный Nonce из 64-битного счетчика (Little Endian)
func makeNonce(counter uint64) []byte {
	nonce := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], counter) // Первые 4 байта нули, затем счетчик
	return nonce
}

// WriteChaff реализует интерфейс ChaffWriter для шейпера
func (c *AEADStreamConn) WriteChaff() error {
	n, _ := rand.Int(rand.Reader, big.NewInt(48))
	chaffLen := 16 + int(n.Int64())

	chaffBytes := make([]byte, 2)
	// Устанавливаем MSB (0x8000) как маркер пустышки для слоя расшифровки
	binary.BigEndian.PutUint16(chaffBytes, uint16(chaffLen)|0x8000)

	return c.writeBlock(chaffBytes, make([]byte, chaffLen))
}

// В методе Write обновляем генерацию 15% шанса для бескомпромиссной криптографии:
func (c *AEADStreamConn) Write(b []byte) (n int, err error) {
	totalWritten := 0

	for len(b) > 0 {
	    // 1. АДАПТИВНЫЙ CHAFFING: С вероятностью 15% перед реальным блоком
        // отправляем случайный мусорный пакет-пустышку (имитация PING/Keep-Alive)
//         randByte := make([]byte, 1)
//         rand.Read(randByte)
//         if randByte[0] < 38 { // ~15% шанс
//             chaffLen := 16 + int(randByte[0]%48) // Короткие пакеты (16-63 байт)
//             chaffBytes := make([]byte, 2)
//             // Устанавливаем старший бит (0x8000) как маркер пустышки
//             binary.BigEndian.PutUint16(chaffBytes, uint16(chaffLen)|0x8000)
//
//             c.writeBlock(chaffBytes, make([]byte, chaffLen)) // Вспомогательная функция записи
//         }
        // 1. АДАПТИВНЫЙ CHAFFING (15% шанс)
        chance, _ := rand.Int(rand.Reader, big.NewInt(100))
        if chance.Int64() < 15 {
            _ = c.WriteChaff() // Переиспользуем наш безопасный метод
        }

        // 2. Обработка реального блока данных
		payloadLen := len(b)
		if payloadLen > maxPayloadSize {
			payloadLen = maxPayloadSize
		}

		payload := b[:payloadLen]
		b = b[payloadLen:]

		// 1. Шифруем длину полезной нагрузки (2 байта) -> дает 2 + 16 (MAC) = 18 байт
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(payloadLen)) // Старший бит = 0

		lenNonce := makeNonce(c.writeCounter)
		c.writeCounter++
		cipherLen := c.writeAEAD.Seal(nil, lenNonce, lenBytes, nil)

		// 2. Шифруем саму полезную нагрузку -> дает payloadLen + 16 (MAC) байт
		payloadNonce := makeNonce(c.writeCounter)
		c.writeCounter++
		cipherPayload := c.writeAEAD.Seal(nil, payloadNonce, payload, nil)

		// Отправляем в сокет (Length Block + Payload Block)
		if _, err := c.Conn.Write(append(cipherLen, cipherPayload...)); err != nil {
			return totalWritten, err
		}

		totalWritten += payloadLen
	}

	return totalWritten, nil
}

// Вспомогательная функция для инкапсуляции записи
func (c *AEADStreamConn) writeBlock(lenBytes, payload []byte) error {
	lenNonce := makeNonce(c.writeCounter)
	c.writeCounter++
	cipherLen := c.writeAEAD.Seal(nil, lenNonce, lenBytes, nil)

	payloadNonce := makeNonce(c.writeCounter)
	c.writeCounter++
	cipherPayload := c.writeAEAD.Seal(nil, payloadNonce, payload, nil)

	_, err := c.Conn.Write(append(cipherLen, cipherPayload...))
	return err
}

func (c *AEADStreamConn) Read(b []byte) (n int, err error) {
    // Обернуто в бесконечный цикл для пропуска Chaff-пакетов
	for {
        if len(c.readBuf) > 0 {
            n = copy(b, c.readBuf)
            c.readBuf = c.readBuf[n:]
            return n, nil
        }

        // 1. Читаем зашифрованную длину (2 байта + 16 байт тег = 18 байт)
        cipherLen := make([]byte, 2+tagSize)
        if _, err := io.ReadFull(c.Conn, cipherLen); err != nil {
            return 0, err
        }

        lenNonce := makeNonce(c.readCounter)
        c.readCounter++

        plainLenBytes, err := c.readAEAD.Open(nil, lenNonce, cipherLen, nil)
        if err != nil {
            return 0, errors.New("aead: invalid length MAC. Possible MitM or corruption")
        }

        // Проверяем флаг пустышки (MSB)
        rawLen := binary.BigEndian.Uint16(plainLenBytes)
        isChaff := (rawLen & 0x8000) != 0
        payloadLen := int(rawLen & 0x7FFF) // Сбрасываем флаг для получения длины

        //payloadLen := int(binary.BigEndian.Uint16(plainLenBytes))
        if payloadLen > maxPayloadSize {
            return 0, errors.New("aead: payload length exceeds maximum")
        }

        // 2. Читаем зашифрованную нагрузку (payloadLen + 16 байт тег)
        cipherPayload := make([]byte, payloadLen+tagSize)
        if _, err := io.ReadFull(c.Conn, cipherPayload); err != nil {
            return 0, err
        }

        payloadNonce := makeNonce(c.readCounter)
        c.readCounter++

        plainPayload, err := c.readAEAD.Open(nil, payloadNonce, cipherPayload, nil)
        if err != nil {
            return 0, errors.New("aead: invalid payload MAC. Possible MitM or corruption")
        }

        // Если это мусор — просто игнорируем его и идем на следующий цикл чтения!
        if isChaff {
            continue
        }

        // 3. Отдаем пользователю
        n = copy(b, plainPayload)
        if n < len(plainPayload) {
            c.readBuf = plainPayload[n:]
        }

        return n, nil
    }
}

// =========================================================================
// AEAD ОБЕРТКА ДЛЯ UDP (СЕССИИ, СЛУЧАЙНЫЙ NONCE)
// =========================================================================

type AEADPacketConn struct {
	net.PacketConn
	readAEAD  cipher.AEAD
	writeAEAD cipher.AEAD
}

func NewAEADPacketConn(conn net.PacketConn, masterSessionKey []byte, isClient bool) (net.PacketConn, error) {
	rAEAD, wAEAD, err := DeriveAEADKeys(masterSessionKey, isClient)
	if err != nil {
		return nil, err
	}
	return &AEADPacketConn{
		PacketConn: conn,
		readAEAD:   rAEAD,
		writeAEAD:  wAEAD,
	}, nil
}

func (c *AEADPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Генерируем случайный 12-байтный Nonce для каждого пакета
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}

	// Шифруем. В результате получаем payloadLen + 16 байт.
	cipherPayload := c.writeAEAD.Seal(nil, nonce, p, nil)

	// Формат кадра: [12 байт Nonce] + [Зашифрованная Нагрузка]
	finalPacket := append(nonce, cipherPayload...)

	_, err = c.PacketConn.WriteTo(finalPacket, addr)
	return len(p), err // Возвращаем длину оригинальной нагрузки
}

func (c *AEADPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Читаем пакет в локальный буфер (макс 64KB для UDP)
	buf := make([]byte, 65536)
	readBytes, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}

	// Минимальная длина пакета = Nonce(12) + MAC(16)
	if readBytes < nonceSize+tagSize {
		return 0, addr, errors.New("aead: udp packet too short")
	}

	// Извлекаем Nonce и зашифрованную часть
	nonce := buf[:nonceSize]
	cipherPayload := buf[nonceSize:readBytes]

	// Расшифровываем
	plainPayload, err := c.readAEAD.Open(nil, nonce, cipherPayload, nil)
	if err != nil {
		return 0, addr, errors.New("aead: invalid udp MAC")
	}

	// Копируем расшифрованные данные в буфер пользователя
	n = copy(p, plainPayload)
	return n, addr, nil
}

