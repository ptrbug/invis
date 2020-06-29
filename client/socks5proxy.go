package main

import (
	"fmt"
	"io"
	"net"

	"github.com/ptrbug/invis/proto"
)

const (
	socks5Version = uint8(5)
)

//cmd type
const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

func handShake(conn net.Conn, version byte, numMethods int, methods []byte) bool {
	if version != socks5Version {
		return false
	}
	resp := []byte{socks5Version, 0}
	_, err := conn.Write(resp)
	if err != nil {
		return false
	}
	return true
}

func readAddr(r io.Reader) (*proto.SOCKS5Address, bool) {
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

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, d *proto.SOCKS5Address) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case d == nil:
		addrType = byte(proto.IPv4)
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case d.AddressType == proto.DOMAINNAME:
		addrType = byte(d.AddressType)
		addrBody = append([]byte{byte(len(d.FQDN))}, d.FQDN...)
		addrPort = d.Port

	case d.AddressType == proto.IPv4:
		addrType = byte(d.AddressType)
		addrBody = []byte(d.IP.To4())
		addrPort = d.Port

	case d.AddressType == proto.IPv6:
		addrType = byte(d.AddressType)
		addrBody = []byte(d.IP.To16())
		addrPort = d.Port

	default:
		return fmt.Errorf("Failed to format address: %v", d)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

func handleSocks5Request(conn net.Conn, firstPacket []byte) {
	defer conn.Close()

	//handshake
	version := firstPacket[0]
	if version != socks5Version {
		return
	}
	numMethods := int(firstPacket[1])
	if numMethods != len(firstPacket)-2 {
		return
	}
	if !handShake(conn, version, numMethods, firstPacket[2:]) {
		return
	}

	//command
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}
	cmd := header[1]
	if cmd != ConnectCommand {
		sendReply(conn, commandNotSupported, nil)
	}

	address, ok := readAddr(conn)
	if !ok {
		sendReply(conn, addrTypeNotSupported, nil)
		return
	}

	sess, streamID := pool.getSessonAndStream(conn)
	if sess == nil {
		sendReply(conn, hostUnreachable, nil)
		return
	}
	defer sess.delStream(streamID)

	err := sendReply(conn, successReply, address)
	if err != nil {
		return
	}

	err = sess.writeServerStreamNew(address, streamID)
	if err != nil {
		return
	}

	//forward
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
