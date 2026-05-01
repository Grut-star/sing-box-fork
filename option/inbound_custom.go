package option

const TypeCustomInternal = "custom_internal"

type CustomInternalInboundOptions struct {
	Listen                   string `json:"listen,omitempty"`
	ListenPort               uint16 `json:"listen_port,omitempty"`
	UnixSocketPath           string `json:"unix_socket_path,omitempty"`
	Token                    string `json:"token,omitempty"`
	Sniff                    bool   `json:"sniff,omitempty"`
	SniffOverrideDestination bool   `json:"sniff_override_destination,omitempty"`
	DomainStrategy           string `json:"domain_strategy,omitempty"`
}