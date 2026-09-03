package eidolon

import (
	"crypto/rand"
	"math/big"
	"net"
	"time"
)

type ChaffWriter interface {
	WriteChaff() error
}

const (
	baseFlushTime = 300 * time.Millisecond
)

// BurstShaperConn объединяет буферизацию (Chunking) и фоновый шум (Cover Traffic).
type BurstShaperConn struct {
	net.Conn
	dataChan          chan []byte
	currentBurstLimit int
}

func NewBurstShaperConn(conn net.Conn) *BurstShaperConn {
	s := &BurstShaperConn{
		Conn:              conn,
		dataChan:          make(chan []byte, 1024),
		currentBurstLimit: generateBurstLimit(), // Инициализируем первый чанк
	}
	go s.shapingLoop()
	return s
}

// generateBurstLimit имитирует реальный плавающий размер сегмента DASH/HLS (от 1MB до 4MB)
func generateBurstLimit() int {
	minBurst := 1 * 1024 * 1024
	maxBurst := 4 * 1024 * 1024

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxBurst-minBurst)))
	return minBurst + int(n.Int64())
}

func (s *BurstShaperConn) Write(b []byte) (int, error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	s.dataChan <- buf
	return len(b), nil
}

func (s *BurstShaperConn) shapingLoop() {
	var pending []byte
	timer := time.NewTimer(getRandomDuration(baseFlushTime))
	defer timer.Stop()

	for {
		select {
		case data, ok := <-s.dataChan:
			if !ok {
				if len(pending) > 0 {
					s.Conn.Write(pending)
				}
				return
			}

			pending = append(pending, data...)

			// Сценарий 1: Накопили динамический объем (Burst).
			if len(pending) >= s.currentBurstLimit {
				s.Conn.Write(pending)
				pending = nil

				// Генерируем новый случайный лимит для следующего чанка
				s.currentBurstLimit = generateBurstLimit()

				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(getRandomDuration(baseFlushTime))
			}

		case <-timer.C:
			// Сценарий 2: Интерактивный трафик (отправляем что есть)
			if len(pending) > 0 {
				s.Conn.Write(pending)
				pending = nil
			} else {
				// Сценарий 3: Фоновый шум (Cover Traffic)
				if chaffer, ok := s.Conn.(ChaffWriter); ok {
					_ = chaffer.WriteChaff()
				}
			}
			timer.Reset(getRandomDuration(baseFlushTime))
		}
	}
}

func getRandomDuration(base time.Duration) time.Duration {
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	jitterPercent := n.Int64()
	multiplier := 0.5 + float64(jitterPercent)/100.0
	return time.Duration(float64(base) * multiplier)
}