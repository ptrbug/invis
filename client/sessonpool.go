package main

import (
	"net"
	"sync"
	"time"

	"github.com/ptrbug/invis/crypto"
	faketls "github.com/ptrbug/invis/tls"
)

type sessionPool struct {
	serverAddr     string
	fakeWebAddr    string
	cert           faketls.Certificate
	channelUUID    []byte
	clientUUID     []byte
	remoteClosedCh chan *session

	cond          *sync.Cond
	tmLastSession time.Time
	isConnecting  bool
	curSession    *session
}

func (p *sessionPool) newSessionPool(serverAddr, fakeWebDomain string, cert faketls.Certificate, channelUUID, clientUUID []byte) *sessionPool {
	return &sessionPool{serverAddr: serverAddr,
		fakeWebAddr:    fakeWebDomain,
		cert:           cert,
		channelUUID:    channelUUID,
		clientUUID:     clientUUID,
		remoteClosedCh: make(chan *session, 8),
		cond:           sync.NewCond(&sync.Mutex{}),
	}
}

func (p *sessionPool) onSessionConnectSucceed(sess *session) {
	tmNow := time.Now()

	p.cond.L.Lock()
	p.tmLastSession = tmNow
	p.isConnecting = false
	if p.curSession != nil {
		p.curSession.autoClose()
	}
	p.curSession = sess
	p.cond.L.Unlock()
	p.cond.Broadcast()
}

func (p *sessionPool) onSessionConnectFailed() {
	p.cond.L.Lock()
	p.isConnecting = false
	p.cond.L.Unlock()
	p.cond.Broadcast()
}

func (p *sessionPool) onSessionRemoteClosed(sess *session) {
	p.cond.L.Lock()
	if p.curSession == sess {
		p.curSession = nil
	}
	p.cond.L.Unlock()
}

func (p *sessionPool) connect() {
	go func() {
		var sess *session
		config := &faketls.Config{
			InsecureSkipVerify: true,
			ServerName:         p.fakeWebAddr,
			ClientExtra: &faketls.ClientExtraConfig{
				RealCertificates:        []faketls.Certificate{p.cert},
				EncodeClientHelloRandom: crypto.NewEncodeHelloRandomFunc(p.channelUUID, p.clientUUID),
			},
		}
		conn, err := faketls.Dial("tcp", p.serverAddr, config)
		if err == nil {
			sess = newSession(conn)
			go sess.agent(p.remoteClosedCh)
		}
		if sess != nil {
			p.onSessionConnectSucceed(sess)
		} else {
			p.onSessionConnectFailed()
		}
	}()
}

func (p *sessionPool) tryConnectWithLock() {
	if p.isConnecting == false {
		p.isConnecting = true
		p.connect()
	}
}

func (p *sessionPool) getSessonAndStream(conn net.Conn) (sess *session, streamID uint16) {

	tryCount := 0
	p.cond.L.Lock()
	for p.curSession == nil {
		tryCount++
		if tryCount > 1 {
			p.cond.L.Unlock()
			return nil, 0
		}
		p.tryConnectWithLock()
		p.cond.Wait()
	}
	sess = p.curSession
	streamID, ok := sess.newStream(conn)
	if !ok {
		p.curSession = nil
		p.cond.L.Unlock()
		return nil, 0
	}
	if streamID >= 10 {
		p.tryConnectWithLock()
	}
	p.cond.L.Unlock()
	return sess, streamID
}

func (p *sessionPool) run() {

	go func() {
		for {
			select {
			case tmNow := <-time.After(time.Minute * 1):
				p.cond.L.Lock()
				if p.curSession != nil {
					if tmNow.After(p.tmLastSession.Add(time.Minute * 5)) {
						p.curSession.autoClose()
						p.curSession = nil
					}
				}
				p.cond.L.Unlock()
			}
		}
	}()

	go func() {
		for {
			select {
			case ss := <-p.remoteClosedCh:
				p.onSessionRemoteClosed(ss)
			}
		}
	}()
}
