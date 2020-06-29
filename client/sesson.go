package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/ptrbug/invis/proto"
)

//Session nop
type session struct {
	curStreamID uint32
	server      net.Conn

	mutex       sync.Mutex
	clients     map[uint16]net.Conn
	isAutoClose bool
	isClosed    bool
}

func newSession(server net.Conn) *session {
	return &session{server: server, clients: make(map[uint16]net.Conn, 16)}
}

func (sess *session) autoClose() {
	sess.mutex.Lock()
	sess.isAutoClose = true
	if len(sess.clients) == 0 {
		sess.server.Close()
	}
	sess.mutex.Unlock()
}

func (sess *session) newStream(conn net.Conn) (uint16, bool) {
	streamID := uint16(atomic.AddUint32(&sess.curStreamID, 1))
	sess.mutex.Lock()
	if sess.isClosed {
		sess.mutex.Unlock()
		return 0, false
	}
	sess.clients[streamID] = conn
	sess.mutex.Unlock()
	return streamID, true
}

func (sess *session) delStream(streamID uint16) {
	sess.mutex.Lock()
	delete(sess.clients, streamID)
	if sess.isAutoClose == true && len(sess.clients) == 0 {
		sess.server.Close()
	}
	sess.mutex.Unlock()
}

func (sess *session) writeServer(data []byte) error {
	_, err := sess.server.Write(data)
	if err != nil {
		sess.server.Close()
	}
	return err
}

func (sess *session) writeServerStreamDel(streamID uint16) error {
	var buffer [proto.HeadLength]byte
	head := proto.MessageHead{}
	head.StreamType = proto.STREAM_DEL
	head.ProtoType = proto.TCP_PROTO
	head.StreamID = streamID
	head.BodyLength = 0
	head.Encode(buffer[:])
	return sess.writeServer(buffer[:])
}

func (sess *session) writeServerStreamNew(addr *proto.SOCKS5Address, streamID uint16) error {
	data := make([]byte, proto.MaxMessageSize)
	length, err := addr.Encode(data[proto.HeadLength:])
	if err != nil {
		return errors.New("SOCKS5Address encode error")
	}

	head := proto.MessageHead{}
	head.StreamType = proto.STREAM_NEW
	head.ProtoType = proto.TCP_PROTO
	head.StreamID = streamID
	head.BodyLength = uint16(length)
	head.Encode(data[0:proto.HeadLength])
	return sess.writeServer(data[0 : proto.HeadLength+int(head.BodyLength)])
}

func (sess *session) writeClient(streamID uint16, data []byte) {
	var conn net.Conn
	sess.mutex.Lock()
	v, ok := sess.clients[streamID]
	if ok {
		conn = v
	}
	sess.mutex.Unlock()

	if conn != nil {
		_, err := conn.Write(data)
		if err != nil {
			conn.Close()
			sess.writeServerStreamDel(streamID)
		}
	}
}

func (sess *session) agent(remoteClosedCh chan<- *session) {
	defer func() {
		sess.server.Close()

		isAutoClose := false
		sess.mutex.Lock()
		for _, conn := range sess.clients {
			conn.Close()
		}
		sess.isClosed = true
		isAutoClose = sess.isAutoClose
		sess.mutex.Unlock()

		if !isAutoClose {
			remoteClosedCh <- sess
		}
	}()

	var buffer [proto.MaxMessageSize]byte

	for {
		_, err := io.ReadFull(sess.server, buffer[:proto.HeadLength])
		if err != nil {
			return
		}

		head := proto.MessageHead{}
		head.Decode(buffer[:proto.HeadLength])
		if head.BodyLength > 0 {
			if head.BodyLength > proto.MaxMessageBodySize {
				return
			}
			_, err = io.ReadFull(sess.server, buffer[proto.HeadLength:proto.HeadLength+int(head.BodyLength)])
			if err != nil {
				return
			}
		}

		if head.ProtoType == proto.TCP_PROTO {
			if head.StreamType == proto.STREAM_DEL {
				sess.delStream(head.StreamID)
			} else if head.StreamType == proto.STREAM_DATA {
				sess.writeClient(head.StreamID, buffer[proto.HeadLength:proto.HeadLength+int(head.BodyLength)])
			} else {
				return
			}
		} else {
			return
		}
	}
}
