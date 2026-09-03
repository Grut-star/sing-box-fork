package option

const TypeUnix = "unix"

type UnixInboundOptions struct {
    InboundOptions `json:",inline,omitempty"`
	ListenTCP    string `json:"listen_tcp"`
	ListenUDP    string `json:"listen_udp"`
	UID          int    `json:"uid"`
	SecurityMode string `json:"security_mode"` // "none", "session", "zerotrust"
	Token        string `json:"token"`

// 	Sniff                    bool   `json:"sniff,omitempty"`
//     SniffOverrideDestination bool   `json:"sniff_override_destination,omitempty"`
//     DomainStrategy           string `json:"domain_strategy,omitempty"`
}