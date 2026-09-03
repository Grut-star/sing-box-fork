package option

// EidolonInboundOptions описывает параметры для серверной части.
type EidolonInboundOptions struct {
	ListenOptions   `mapstructure:",squash"`
	MasterSecret    string   `json:"master_secret"` // Ключ для проверки TOTP
	Dest            string   `json:"dest"`          // Сайт-донор для Zero-Delay Fallback (напр. microsoft.com:443)
	ServerNames     []string `json:"server_names"`  // Ожидаемые SNI
	PrivateKey      string   `json:"private_key"`   // Для эфемерной криптографии
	TLS *InboundTLSOptions `json:"tls,omitempty"`
    Federation *EidolonFederationOptions `json:"federation,omitempty"`
}

type EidolonFederationOptions struct {
	Enabled  bool   `json:"enabled"`
	OporaURL string `json:"opora_url"`
	Token    string `json:"token"`
	PubKey   string `json:"pub_key"`
}