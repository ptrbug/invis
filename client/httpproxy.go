package main

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ptrbug/invis/proto"
)

func handleHTTPRequest(conn net.Conn, firstPacket []byte) {
	defer conn.Close()

	var method, rawurl, host string
	var port int
	index := bytes.IndexByte(firstPacket, '\n')
	if index == -1 {
		return
	}
	fmt.Sscanf(string(firstPacket), "%s%s", &method, &rawurl)
	if method == "CONNECT" {
		xhost, xport, err := net.SplitHostPort(rawurl)
		if err != nil {
			return
		}
		host = xhost
		port, err = strconv.Atoi(xport)
		if err != nil {
			return
		}
	} else {
		URL, err := url.Parse(rawurl)
		if err != nil {
			return
		}

		xhost, xport, err := net.SplitHostPort(URL.Host)
		if err != nil {
			host = URL.Host
			port = 80
		} else {
			host = xhost
			port, err = strconv.Atoi(xport)
			if err != nil {
				return
			}
		}
	}

	sess, streamID := pool.getSessonAndStream(conn)
	if sess == nil {
		return
	}
	defer sess.delStream(streamID)

	addr := &proto.SOCKS5Address{}
	addr.AddressType = proto.DOMAINNAME
	addr.FQDN = host
	addr.Port = uint16(port)
	err := sess.writeServerStreamNew(addr, streamID)
	if err != nil {
		return
	}

	if method == "CONNECT" {
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		var header [proto.HeadLength]byte
		head := proto.MessageHead{}
		head.StreamType = proto.STREAM_DATA
		head.ProtoType = proto.TCP_PROTO
		head.StreamID = streamID
		head.BodyLength = uint16(len(firstPacket))
		head.Encode(header[:])
		err := sess.writeServer(header[:])
		if err != nil {
			return
		}
		err = sess.writeServer(firstPacket)
		if err != nil {
			return
		}
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
