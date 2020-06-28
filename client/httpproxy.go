package main

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ptrbug/invis/proto"
)

func handleHTTPRequest(conn net.Conn, firstPacket []byte, firstPacketLength int) {
	defer conn.Close()

	var method, rawurl, host string
	var port int
	index := bytes.IndexByte(firstPacket[proto.HeadLength:], '\n')
	if index == -1 {
		return
	}
	fmt.Sscanf(string(firstPacket[proto.HeadLength:]), "%s%s", &method, &rawurl)
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

	err := sess.writeServerStreamNew(host, uint16(port), streamID)
	if err != nil {
		return
	}

	if method == "CONNECT" {
		fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		head := proto.MessageHead{}
		head.StreamType = proto.STREAM_DATA
		head.ProtoType = proto.TCP_PROTO
		head.StreamID = streamID
		head.BodyLength = uint16(firstPacketLength)
		head.Encode(firstPacket[0:proto.HeadLength])
		err := sess.writeServer(firstPacket[:proto.HeadLength+firstPacketLength])
		if err != nil {
			return
		}
	}

	buffer := firstPacket[:]
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
