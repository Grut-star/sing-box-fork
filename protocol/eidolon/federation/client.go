package federation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type EidolonClient struct {
	OporaURL       string
	BootstrapToken string
	OporaPubKey    ed25519.PublicKey // Жестко вшитый публичный ключ Опоры!
}

func NewEidolonClient(oporaURL, token, pubKeyHex string) (*EidolonClient, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	return &EidolonClient{
		OporaURL:       oporaURL,
		BootstrapToken: token,
		OporaPubKey:    ed25519.PublicKey(pubKeyBytes),
	}, nil
}

// FetchInitialConfig делает ПРЯМОЙ запрос к Опоре. Вызывается СТРОГО 1 раз при запуске.
func (c *EidolonClient) FetchInitialConfig() (*FederationState, error) {
	// Используем дефолтный HTTP-клиент (прямой выход в сеть)
	return c.doFetch(http.DefaultClient)
}

// FetchUpdateConfig запрашивает обновления ТРАНЗИТОМ через рабочие узлы.
// dialer должен быть функцией маршрутизации от ядра sing-box, направляющей трафик в туннель.
func (c *EidolonClient) FetchUpdateConfig(tunneledClient *http.Client) (*FederationState, error) {
	// Используем клиент, чей Transport.DialContext завернут в наш Outbound
	return c.doFetch(tunneledClient)
}

// doFetch содержит общую логику загрузки и строгой криптографической проверки
func (c *EidolonClient) doFetch(httpClient *http.Client) (*FederationState, error) {
	req, err := http.NewRequest("GET", c.OporaURL+"/api/v1/bootstrap", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.BootstrapToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("opora rejected bootstrap request")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var state FederationState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, err
	}

	// 1. Извлекаем подпись
	sigBytes, err := hex.DecodeString(state.Signature)
	if err != nil {
		return nil, errors.New("invalid signature format")
	}

	// 2. Восстанавливаем оригинальный JSON (без поля signature) для проверки
	rawPayload, _ := json.Marshal(map[string]interface{}{
		"nodes":         state.Nodes,
		"master_secret": state.MasterSecret,
		"timestamp":     state.Timestamp,
	})

	// 3. БЕСКОМПРОМИССНАЯ БЕЗОПАСНОСТЬ: Проверяем подпись Ed25519
	// Если цензор или провайдер подменил данные, подпись не сойдется, и клиент оборвет связь!
	if !ed25519.Verify(c.OporaPubKey, rawPayload, sigBytes) {
		return nil, errors.New("CRITICAL: Opora signature verification failed! Possible MITM attack")
	}

	return &state, nil
}