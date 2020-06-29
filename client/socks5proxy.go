package main

import (
	"bufio"
	"io"
	"net"

	"github.com/ptrbug/invis/proto"
)

func handShake(conn net.Conn, version byte, numMethods int, methods []byte) bool {
	if version != 5 {
		return false
	}
	resp := []byte{5, 0}
	_, err := conn.Write(resp)
	if err != nil {
		return false
	}
	return true
}

func readAddr(r *bufio.Reader) (*proto.SOCKS5Address, bool) {
	d := &proto.SOCKS5Address{}

	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, false
	}
	d.AddressType = proto.AddressType(addrType[0])

	// Handle on a per type basis
	switch d.AddressType {
	case proto.IPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, false
		}
		d.IP = net.IP(addr)

	case proto.IPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, false
		}
		d.IP = net.IP(addr)

	case proto.DOMAINNAME:
		if _, err := r.Read(addrType); err != nil {
			return nil, false
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, false
		}
		d.FQDN = string(fqdn)

	default:
		return nil, false
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, false
	}
	d.Port = (uint16(port[0]) << 8) | uint16(port[1])

	return d, true
}

func handleSocks5Request(conn net.Conn, firstPacket []byte) {
	defer conn.Close()

	version := firstPacket[0]
	if version != 5 {
		return
	}
	numMethods := int(firstPacket[1])
	if numMethods != len(firstPacket)-2 {
		return
	}
	if !handShake(conn, version, numMethods, firstPacket[2:]) {
		return
	}

	r := bufio.NewReader(conn)

	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(r, header, 3); err != nil {
		return
	}

	if header[0] != 5 && header[1] != 1 {
		return
	}

	address, ok := readAddr(r)
	if !ok {
		return
	}

	/*
		+----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(resp)

	sess, streamID := pool.getSessonAndStream(conn)
	if sess == nil {
		return
	}
	defer sess.delStream(streamID)

	err := sess.writeServerStreamNew(address, streamID)
	if err != nil {
		return
	}

	buffer := make([]byte, proto.MaxMessageSize)

	for {
		n, err := conn.Read(buffer[proto.HeadLength:])
		if err != nil {
			sess.writeServerStreamDel(streamID)
			return
		}

		head := proto.MessageHead{}
		head.StreamType = proto.STREAM_DATA
		head.ProtoType = proto.TCP_PROTO
		head.StreamID = streamID
		head.BodyLength = uint16(n)
		head.Encode(buffer[0:proto.HeadLength])
		err = sess.writeServer(buffer[:proto.HeadLength+n])
		if err != nil {
			return
		}
	}
}
