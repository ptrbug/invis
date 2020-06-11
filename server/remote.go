package main

import (
	"net"
	"sync"

	"github.com/ptrbug/invis/proto"
)

//Remote nop
type Remote struct {
	sess     *Session
	toStopCh chan bool
	die      chan struct{}
	msgQueue chan []byte
	msgCache [][]byte

	mutex    sync.Mutex
	isStoped bool
	server   net.Conn
}

func newRemote(sess *Session) *Remote {
	return &Remote{sess: sess,
		toStopCh: make(chan bool, 1),
		die:      make(chan struct{}),
		msgQueue: make(chan []byte, 8),
		msgCache: make([][]byte, 0, 8)}
}

func (remote *Remote) stop(isServerClose bool) {
	select {
	case remote.toStopCh <- isServerClose:
	default:
	}
}

func (remote *Remote) send(data []byte) {
	select {
	case remote.msgQueue <- data:
	case <-remote.die:
	}
}

func (remote *Remote) agent(StreamID uint16, address string) {

	connected := make(chan net.Conn, 1)

	go func() {

		isServerClose := <-remote.toStopCh
		if isServerClose {
			remote.sess.remoteStreamDel(StreamID)
		}
		close(remote.die)

		remote.mutex.Lock()
		remote.isStoped = true
		if remote.server != nil {
			remote.server.Close()
			remote.server = nil
		}
		remote.mutex.Unlock()
	}()

	go func() {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			remote.stop(true)
			return
		}

		remote.mutex.Lock()
		if remote.isStoped {
			conn.Close()
			remote.mutex.Unlock()
			return
		}
		remote.mutex.Unlock()

		connected <- conn
		var buffer [proto.MaxMessageSize]byte
		for {
			n, err := conn.Read(buffer[proto.HeadLength:])
			if err != nil {
				remote.stop(true)
				return
			}

			head := proto.MessageHead{}
			head.StreamType = proto.STREAM_DATA
			head.ProtoType = proto.TCP_PROTO
			head.StreamID = StreamID
			head.BodyLength = uint16(n)
			head.Encode(buffer[:proto.HeadLength])
			remote.sess.write(buffer[:proto.HeadLength+int(head.BodyLength)])
		}
	}()

	var server net.Conn
	for {
		select {
		case data := <-remote.msgQueue:
			if server != nil {
				_, err := server.Write(data)
				if err != nil {
					remote.stop(true)
					return
				}
			} else {
				remote.msgCache = append(remote.msgCache, data)
			}
		case server = <-connected:
			for _, data := range remote.msgCache {
				_, err := server.Write(data)
				if err != nil {
					remote.stop(true)
					return
				}
			}
			remote.msgCache = nil
		case <-remote.die:
			return
		}

	}
}
