package eidolon

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"sync"
	"time"
)

const timeWindow = 5 // Окно валидности токена в секундах

var (
	currentTokens sync.Map     // Текущий кэш токенов
	pastTokens    sync.Map     // Предыдущий кэш токенов (для мягкого перехода)
	cacheMutex    sync.RWMutex // Защита от состояния гонки при ротации
)

func init() {
	// Фоновый воркер ротации кэша каждые 10 секунд.
	// Гарантирует, что старые токены удаляются, а окно жизни не превышает 20 секунд.
	go func() {
		for {
			time.Sleep(10 * time.Second)
			cacheMutex.Lock()
			pastTokens = currentTokens
			currentTokens = sync.Map{}
			cacheMutex.Unlock()
		}
	}()
}

// GenerateToken генерирует 32-байтный HMAC.
// Жестко привязан к KeyShare (Context-Bound), чтобы исключить подмену ключей цензором.
func GenerateToken(secret string, offset int64, keyShare []byte) []byte {
	t := (time.Now().Unix() / timeWindow) + offset
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(buf)

	if len(keyShare) > 0 {
		mac.Write(keyShare) // Контекстная привязка к эфемерному ключу клиента
	}
	return mac.Sum(nil)
}

// ValidateTokenConstantTime проверяет токен за строго константное время (защита от тайминг-атак).
func ValidateTokenConstantTime(secret string, token []byte, keyShare []byte) bool {
	if len(token) != 32 {
		return false
	}

	isValid := byte(0)

	// Мы всегда проверяем все 3 окна (предыдущее, текущее, следующее),
	// даже если совпадение найдено на первом шаге. Это исключает тайминг-атаки.
	for offset := int64(-1); offset <= 1; offset++ {
		expected := GenerateToken(secret, offset, keyShare)

		// subtle.ConstantTimeCompare выполняется за одинаковое время
		// независимо от того, на каком байте произошло несовпадение
		match := subtle.ConstantTimeCompare(token, expected)
		isValid = isValid | byte(match)
	}

	// Если токен валиден криптографически, проверяем его на Replay (повторное использование)
	if isValid == 1 {
		tokenStr := string(token) // Защита от атаки Drop-and-Replay

		// Читаем из обеих мап под RLock
		cacheMutex.RLock()
		_, inCurrent := currentTokens.Load(tokenStr)
		_, inPast := pastTokens.Load(tokenStr)
		cacheMutex.RUnlock()

		if inCurrent || inPast {
			// Токен верный, но уже был использован! Это Drop-and-Replay атака.
			return false
		}

		// Запоминаем токен, чтобы его нельзя было использовать повторно
		currentTokens.Store(tokenStr, true)
		return true
	}

	return false
}