package federation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// NodeConfig описывает рабочий узел федерации
type NodeConfig struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
	SNI  string `json:"sni"`
	Dest string `json:"dest"` // Сайт-донор для Fallback'а
}

// FederationState — это то, что отправляется клиенту
type FederationState struct {
	Nodes        []NodeConfig `json:"nodes"`
	MasterSecret string       `json:"master_secret"`
	Timestamp    int64        `json:"timestamp"`
	Signature    string       `json:"signature"` // Подпись Ed25519 (проверяется клиентом)
}

type OporaServer struct {
	PrivateKey     ed25519.PrivateKey
	BootstrapToken string // Токен для защиты от случайных сканеров
	CurrentState   FederationState
}

func NewOporaServer(privKeyHex, bootstrapToken string) (*OporaServer, error) {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, err
	}

	return &OporaServer{
		PrivateKey:     ed25519.PrivateKey(privKeyBytes),
		BootstrapToken: bootstrapToken,
	}, nil
}

// UpdateState ротирует узлы и секреты, подписывая новое состояние
func (o *OporaServer) UpdateState(nodes []NodeConfig, newMasterSecret string) {
	state := FederationState{
		Nodes:        nodes,
		MasterSecret: newMasterSecret,
		Timestamp:    time.Now().Unix(),
	}

	// Сериализуем данные для подписи (без поля Signature)
	rawPayload, _ := json.Marshal(map[string]interface{}{
		"nodes":         state.Nodes,
		"master_secret": state.MasterSecret,
		"timestamp":     state.Timestamp,
	})

	// Криптографическая подпись состояния
	signature := ed25519.Sign(o.PrivateKey, rawPayload)
	state.Signature = hex.EncodeToString(signature)

	o.CurrentState = state
}

// HandleBootstrap — HTTP-обработчик для выдачи конфигов
func (o *OporaServer) HandleBootstrap(w http.ResponseWriter, r *http.Request) {
	// 1. Простая защита от цензоров (Требуем Bearer токен)
	if r.Header.Get("Authorization") != "Bearer "+o.BootstrapToken {
		w.WriteHeader(http.StatusNotFound) // Скрываем наличие API
		return
	}

	// 2. Отдаем подписанное состояние
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(o.CurrentState)
}

// Start запускает скрытый сервер Опоры (рекомендуется ставить за Caddy/Nginx)
func (o *OporaServer) Start(listenAddr string) error {
	http.HandleFunc("/api/v1/bootstrap", o.HandleBootstrap)
	return http.ListenAndServe(listenAddr, nil)
}