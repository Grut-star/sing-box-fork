package option

// EidolonOutboundOptions описывает параметры для клиентской части.
type EidolonOutboundOptions struct {
	DialerOptions  `mapstructure:",squash"`
	Server         string `json:"server"`
	ServerPort     uint16 `json:"server_port"`
	MasterSecret   string `json:"master_secret"` // Ключ для генерации TOTP
	ServerName     string `json:"server_name"`   // SNI для маскировки
	PublicKey      string `json:"public_key"`    // Публичный ключ сервера
}