package main

import (
	"net"

	"github.com/ptrbug/invis/proto"
)

//Session nop
type Session struct {
	client            net.Conn
	streams           map[uint16]*Remote
	remoteStreamDelCh chan uint16
	clientWriteErrCh  chan error
	Die               chan struct{}
}

func newSession(client net.Conn) *Session {
	return &Session{
		client:            client,
		streams:           make(map[uint16]*Remote, 16),
		remoteStreamDelCh: make(chan uint16, 16),
		clientWriteErrCh:  make(chan error, 1),
		Die:               make(chan struct{})}
}

func (sess *Session) write(data []byte) {
	_, err := sess.client.Write(data)
	if err != nil {
		select {
		case sess.clientWriteErrCh <- err:
		case <-sess.Die:
			break
		}
	}
}

func (sess *Session) remoteStreamDel(StreamID uint16) {
	select {
	case sess.remoteStreamDelCh <- StreamID:
	case <-sess.Die:
		break
	}
}

func (sess *Session) agent(in <-chan *proto.Message) {

	defer func() {
		sess.client.Close()
		close(sess.Die)
		for _, remote := range sess.streams {
			remote.stop(false)
		}
	}()

	for {
		select {
		case msg, ok := <-in:
			if !ok {
				return
			}
			if msg.Head.ProtoType == proto.TCP_PROTO {
				if msg.Head.StreamType == proto.STREAM_NEW {
					_, ok := sess.streams[msg.Head.StreamID]
					if ok {
						return
					}
					address := &proto.SOCKS5Address{}
					_, err := address.Decode(msg.Body[0:msg.Head.BodyLength])
					if err != nil {
						return
					}
					remote := newRemote(sess)
					sess.streams[msg.Head.StreamID] = remote
					go remote.agent(msg.Head.StreamID, address.String())

				} else if msg.Head.StreamType == proto.STREAM_DEL {
					remote, ok := sess.streams[msg.Head.StreamID]
					if ok {
						delete(sess.streams, msg.Head.StreamID)
						remote.stop(false)
					}

				} else if msg.Head.StreamType == proto.STREAM_DATA {
					remote, ok := sess.streams[msg.Head.StreamID]
					if ok {
						remote.send(msg.Body[0:msg.Head.BodyLength])
					}
				} else {
					return
				}
			} else {
				return
			}

		case StreamID := <-sess.remoteStreamDelCh:
			delete(sess.streams, StreamID)
			head := proto.MessageHead{}
			head.StreamType = proto.STREAM_DEL
			head.ProtoType = proto.TCP_PROTO
			head.StreamID = StreamID
			head.BodyLength = 0
			var data [proto.HeadLength]byte
			head.Encode(data[:])
			sess.write(data[:])

		case <-sess.clientWriteErrCh:
			return
		}
	}
}
