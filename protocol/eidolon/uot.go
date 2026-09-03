package eidolon

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	M "github.com/sagernet/sing/common/metadata"
)

func writeDestination(conn net.Conn, dest M.Socksaddr, isUDP bool) error {
	destStr := dest.String()
	buf := make([]byte, 3+len(destStr))

	if isUDP {
		buf[0] = 0x01
	} else {
		buf[0] = 0x00
	}

	binary.BigEndian.PutUint16(buf[1:3], uint16(len(destStr)))
	copy(buf[3:], destStr)

	_, err := conn.Write(buf)
	return err
}

func EncapsulateUDPoverStream(conn net.Conn) net.PacketConn {
	return &uoTStreamPacketConn{Conn: conn}
}

type uoTStreamPacketConn struct {
	net.Conn
}

func (c *uoTStreamPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}
	if int(length) > len(p) {
		return 0, nil, errors.New("UoT: packet exceeds buffer size")
	}
	n, err = io.ReadFull(c.Conn, p[:length])
	return n, c.Conn.RemoteAddr(), err
}

func (c *uoTStreamPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if len(p) > 65535 {
		return 0, errors.New("UoT: packet too large")
	}
	buf := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(p)))
	copy(buf[2:], p)
	_, err = c.Conn.Write(buf)
	return len(p), err
}