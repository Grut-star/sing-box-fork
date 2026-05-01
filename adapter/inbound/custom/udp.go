package custom

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing-box/common/process"
	M "github.com/sagernet/sing/common/metadata"
)

var ExpectedToken = []byte("NEKOTOKN")

type udpPacket struct {
	payload []byte
	addr    net.Addr
}

type virtualUDPConn struct {
	inbound    *Inbound
	clientAddr *net.UDPAddr
	readCh     chan *udpPacket
	ctx        context.Context
	cancel     context.CancelFunc
}

func (c *virtualUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, io.EOF
	case pkt := <-c.readCh:
		n = copy(p, pkt.payload)
		return n, pkt.addr, nil
	}
}

func (c *virtualUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}

	var ipBytes []byte
	var flag byte

	if ip4 := udpAddr.IP.To4(); ip4 != nil {
		flag = 0x04
		ipBytes = ip4
	} else {
		flag = 0x06
		ipBytes = udpAddr.IP.To16()
	}

	headerLen := 8 + 1 + len(ipBytes) + 2
	out := make([]byte, headerLen+len(p))

	// Сборка заголовка
	copy(out[0:8], []byte(c.inbound.options.Token))
	out[8] = flag
	copy(out[9:9+len(ipBytes)], ipBytes)
	binary.BigEndian.PutUint16(out[9+len(ipBytes):9+len(ipBytes)+2], uint16(udpAddr.Port))

	// Данные
	copy(out[headerLen:], p)

	_, err = c.inbound.udpListener.WriteToUDP(out, c.clientAddr)
	return len(p), err
}

func (c *virtualUDPConn) Close() error {
	c.cancel()
	c.inbound.udpSessions.Delete(c.clientAddr.String())
	return nil
}

func (c *virtualUDPConn) LocalAddr() net.Addr                { return c.inbound.udpListener.LocalAddr() }
func (c *virtualUDPConn) SetDeadline(t time.Time) error      { return nil }
func (c *virtualUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *virtualUDPConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *virtualUDPConn) Upstream() any           { return nil } // Важно: nil для избежания рекурсии
func (c *virtualUDPConn) ReaderReplaceable() bool { return false }

func (i *Inbound) acceptUDP() {
	buf := make([]byte, 65535)


	for {
		n, clientAddr, err := i.udpListener.ReadFromUDP(buf)
		if err != nil {
			if i.closed {
				return
			}
			i.logger.Error("udp read error: ", err)
			continue
		}

		if n < 15 {
			continue
		}

		if !bytes.Equal(buf[:8], []byte(i.options.Token)) {
			i.logger.Error("SECURITY DROP: Invalid UDP token from ", clientAddr, " packet size: ", n)
			continue
		}

		flag := buf[8]
		var destIP net.IP
		var destPort uint16
		var payloadOffset int

		if flag == 0x04 {
			if n < 15 { continue }
			destIP = net.IP(buf[9:13])
			destPort = binary.BigEndian.Uint16(buf[13:15])
			payloadOffset = 15
		} else if flag == 0x06 {
			if n < 27 { continue }
			destIP = net.IP(buf[9:25])
			destPort = binary.BigEndian.Uint16(buf[25:27])
			payloadOffset = 27
		} else {
			continue
		}
        i.logger.Info("Nekodesk-Go: UDP Packet wrapped! Target IP: ", destIP.String(), ":", destPort)

		payload := make([]byte, n-payloadOffset)
		copy(payload, buf[payloadOffset:n])

		destAddr := &net.UDPAddr{IP: destIP, Port: int(destPort)}
		sessionKey := clientAddr.String()

		vConnObj, exists := i.udpSessions.Load(sessionKey)
		var vConn *virtualUDPConn

		if !exists {
		    i.logger.Info("UDP New Session: ", clientAddr.String(), " -> ", destAddr.String())
			ctx, cancel := context.WithCancel(i.ctx)
			vConn = &virtualUDPConn{
				inbound:    i,
				clientAddr: clientAddr,
				readCh:     make(chan *udpPacket, 256),
				ctx:        ctx,
				cancel:     cancel,
			}
			i.udpSessions.Store(sessionKey, vConn)

			go func(vc *virtualUDPConn, target *net.UDPAddr) {
				metadata := adapter.InboundContext{
					Inbound:     i.tag,
					InboundType: i.Type(),
					Source:      M.ParseSocksaddr(vc.clientAddr.String()), // Добавили источник
				    ProcessInfo: &process.Info{UserId: int32(os.Getuid())},
				}

				if targetAddr, ok := netip.AddrFromSlice(target.IP); ok {
					metadata.Destination = M.SocksaddrFrom(targetAddr, uint16(target.Port))
				}

				packetConn := bufio.NewPacketConn(vc)
				// ВАЖНО: Мы НЕ вызываем vc.Close() здесь.
				// sing-box сам закроет PacketConn, когда сессия в роутере завершится.
				i.router.RoutePacketConnectionEx(i.ctx, packetConn, metadata, nil)
			}(vConn, destAddr)
		} else {
			vConn = vConnObj.(*virtualUDPConn)
		}

		select {
		case vConn.readCh <- &udpPacket{payload: payload, addr: destAddr}:
		default:
			i.logger.Error("udp session channel full")
		}
	}
}