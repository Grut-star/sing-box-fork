package custom

import (
    "context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"strconv"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/common/process"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type Options struct {
    Listen                   string `json:"listen"`
	ListenPort               uint16 `json:"listen_port"` // Оставляем для совместимости, но использовать не будем
	UnixSocketPath           string `json:"unix_socket_path"`
	ControlSocketPath        string `json:"control_socket_path"`
	Token                    string `json:"token"`
	Sniff                    bool   `json:"sniff,omitempty"`
	SniffOverrideDestination bool   `json:"sniff_override_destination,omitempty"`
	DomainStrategy           string `json:"domain_strategy,omitempty"`
}

var _ adapter.Inbound = (*Inbound)(nil)

type Inbound struct {
	ctx         context.Context
	logger      log.ContextLogger
	router      adapter.ConnectionRouterEx
	options     Options
	tag         string
	tcpListener net.Listener
	udpListener *net.UDPConn
	udpSessions sync.Map
	done        chan struct{}
	closed      bool
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
	return &Inbound{
		ctx:     ctx,
		logger:  logger,
		router:  router,
		options: options,
		tag:     tag,
		done:    make(chan struct{}),
	}, nil
}

func (i *Inbound) Type() string { return "custom_internal" }
func (i *Inbound) Tag() string  { return i.tag }

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	var err error
	// На Android используем Unix Socket, на Windows - TCP для тестов
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		i.tcpListener, err = net.Listen("unix", i.options.UnixSocketPath)
	} else {
		i.tcpListener, err = net.Listen("tcp", "127.0.0.1:10801")
	}

	if err != nil {
		return E.Cause(err, "listen tcp/unix socket")
	}

	// UDP Socket: Используем Port: 0 для динамического выделения
    udpAddr := &net.UDPAddr{IP: net.ParseIP(i.options.Listen), Port: 0}
    i.udpListener, err = net.ListenUDP("udp", udpAddr)
    if err != nil {
        i.tcpListener.Close()
        return E.Cause(err, "listen udp")
    }

    // Получаем реально выделенный порт
    actualUdpPort := i.udpListener.LocalAddr().(*net.UDPAddr).Port

    // Control Socket (AF_UNIX)
    if runtime.GOOS == "linux" || runtime.GOOS == "android" {
        ctrlListener, err := net.Listen("unix", i.options.ControlSocketPath)
        if err != nil {
            return E.Cause(err, "listen control unix socket")
        }
        go i.acceptControl(ctrlListener, actualUdpPort)
    }

	go i.acceptTCP()
	go i.acceptUDP()

	i.logger.Info("custom_internal started. Token: ", i.options.Token)
	return nil
}

func (i *Inbound) acceptControl(l net.Listener, udpPort int) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if i.closed { return }
			continue
		}

		go func(c net.Conn) {
			defer c.Close()

			// todo добавить
			// Опционально: здесь можно добавить такую же проверку SO_PEERCRED, как в acceptTCP

			// Формируем бинарный пакет: 8 байт Токен + 2 байта Порт (BigEndian)
			resp := make([]byte, 10)
			copy(resp[0:8], []byte(i.options.Token))
			binary.BigEndian.PutUint16(resp[8:10], uint16(udpPort))

			c.Write(resp)
		}(conn)
	}
}

func (i *Inbound) Close() error {
	i.closed = true
	close(i.done)
	if i.tcpListener != nil { i.tcpListener.Close() }
	if i.udpListener != nil { i.udpListener.Close() }
	return nil
}

func (i *Inbound) acceptTCP() {
    // Получаем UID текущего процесса (по идее NekoDesk)
	myUid := uint32(os.Getuid())

	for {
		conn, err := i.tcpListener.Accept()
		if err != nil {
			if i.closed {
				return
			}
			i.logger.Error("tcp accept error: ", err)
			continue
		}

		go func(c net.Conn) {
			//defer c.Close() идиотизм

            // 1. Проверка SO_PEERCRED для Linux / Android
            if unixConn, ok := c.(*net.UnixConn); ok {
                sysConn, err := unixConn.SyscallConn()
                if err != nil {
                    i.logger.Error("failed to get syscall conn: ", err)
                    c.Close()
                    return
                }

                var cred *syscall.Ucred
                var credErr error

                // Опускаемся на уровень системных вызовов через Control-замыкание
                err = sysConn.Control(func(fd uintptr) {
                    cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
                })

                if err != nil || credErr != nil || cred == nil {
                    i.logger.Error("failed to get peercred")
                    c.Close()
                    return
                }

                // Сверяем UID.
                if cred.Uid != myUid {
                    i.logger.Error("unauthorized AF_UNIX access attempt from UID: ", cred.Uid)
                    c.Close()
                    return
                }

                i.logger.Trace("AF_UNIX peercred authorized for UID: ", cred.Uid)
            } else {
                i.logger.Trace("non-unix connection, skipping SO_PEERCRED check")
            }

            // 2. Читаем заголовок NekoDesk, отправленный из C++ (GeckoView)
            peekBuf := make([]byte, 9)
            if _, err := io.ReadFull(c, peekBuf); err != nil {
                i.logger.Error("failed to read tcp token: ", err)
                c.Close()
                return
            }

            if string(peekBuf[:8]) != i.options.Token {
                i.logger.Error("SECURITY DROP: Invalid TCP token")
                c.Close()
                return
            }

            flag := peekBuf[8]
            var destStr string
            var destPort uint16
            //var destIP net.IP

            if flag == 0x03 {
                // Домен: читаем 1 байт длины
                lenBuf := make([]byte, 1)
                if _, err := io.ReadFull(c, lenBuf); err != nil {
                    c.Close()
                    return
                }
                domainLen := int(lenBuf[0])

                // Читаем сам домен + 2 байта порта
                domainPortBuf := make([]byte, domainLen+2)
                if _, err := io.ReadFull(c, domainPortBuf); err != nil {
                    c.Close()
                    return
                }

                destStr = string(domainPortBuf[:domainLen])
                destPort = binary.BigEndian.Uint16(domainPortBuf[domainLen:])
            } else if flag == 0x04 {
                // IPv4
                ipPortBuf := make([]byte, 6)
                if _, err := io.ReadFull(c, ipPortBuf); err != nil {
                    c.Close()
                    return
                }
                destStr = net.IP(ipPortBuf[:4]).String()
                destPort = binary.BigEndian.Uint16(ipPortBuf[4:6])
            } else if flag == 0x06 {
                // IPv6
                ipPortBuf := make([]byte, 18)
                if _, err := io.ReadFull(c, ipPortBuf); err != nil {
                    c.Close()
                    return
                }
                destStr = net.IP(ipPortBuf[:16]).String()
                destPort = binary.BigEndian.Uint16(ipPortBuf[16:18])
            } else {
                i.logger.Error("Unknown IP flag in TCP header: ", flag)
                c.Close()
                return
            }

            i.logger.Info("Nekodesk-Go: TCP Header received! Target: ", destStr, ":", destPort)


            i.logger.Trace("TCP Intercepted connection to ", destStr, ":", destPort)

            // 3. Формируем InboundContext с правильным Destination
            metadata := adapter.InboundContext{
                Inbound:     i.tag,
                InboundType: i.Type(),
                Destination: M.ParseSocksaddr(destStr + ":" + strconv.Itoa(int(destPort))),
                Source:      M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 10800),// фейковый источник чтобы не ругался
                ProcessInfo: &process.Info{
                					UserId: int32(myUid),
                				},
            }

            // 4. Отправляем в ядро sing-box для маршрутизации
            i.router.RouteConnectionEx(i.ctx, c, metadata, nil)
        }(conn) // todo Перепроверить эффективность защиты и tcp и udp. На всякий случай лучше перебдеть.
	}
}