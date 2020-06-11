package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ptrbug/invis/crypto"
	"github.com/ptrbug/invis/proto"
	faketls "github.com/ptrbug/invis/tls"
)

type clientInfo struct {
	ID         string
	ListenAddr string
}

type appConfig struct {
	FakeWebURL        string
	FrontedListenAddr string
	Channel           string
	Clients           []clientInfo
}

type tlsServerConfig struct {
	cert       faketls.Certificate
	uuid       uuid.UUID
	listenAddr string
}

type tlsServerMangerConfig struct {
	channel            uuid.UUID
	maxVersion         uint16
	getFakeCertificate func() *faketls.Certificate
	tlsServers         *map[uuid.UUID]*tlsServerConfig
}

func main() {

	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		fmt.Println("config.json reading error", err)
		return
	}

	appcfg := appConfig{}
	err = json.Unmarshal(data, &appcfg)
	if err != nil {
		fmt.Println("Unmarshal config.json file error", err)
		return
	}

	channel, err := uuid.Parse(appcfg.Channel)
	if err != nil {
		fmt.Printf("channel uuid:%v parse error", appcfg.Channel)
		return
	}

	tlsServers := make(map[uuid.UUID]*tlsServerConfig, len(appcfg.Clients))
	for _, v := range appcfg.Clients {
		uuid, err := uuid.Parse(v.ID)
		if err != nil {
			fmt.Printf("client uuid:%v parse error", v.ID)
			return
		}
		cert, err := crypto.CreateX509KeyPair(uuid[:], 2048)
		if err != nil {
			fmt.Printf("createX509KeyPair:%v error", uuid)
			return
		}

		cfg := &tlsServerConfig{}
		cfg.uuid = uuid
		cfg.cert = cert
		cfg.listenAddr = v.ListenAddr
		tlsServers[uuid] = cfg
	}

	url, err := url.Parse(appcfg.FakeWebURL)
	if err != nil {
		return
	}
	webAddr := url.Host
	if strings.Index(webAddr, ":") == -1 {
		webAddr += ":443"
	}

	webCert := &webCert{webAddr: webAddr}
	maxVersion, err := webCert.updateWebCert()
	if err != nil {
		fmt.Printf("updateCert:%v error", err)
	}
	go webCert.checkUpdateOnTimer()

	tlsServerMgrCfg := &tlsServerMangerConfig{channel: channel,
		maxVersion:         maxVersion,
		getFakeCertificate: webCert.getCert,
		tlsServers:         &tlsServers,
	}
	tlsServerAddrs, err := startTLSServ(tlsServerMgrCfg)
	if err != nil {
		return
	}

	runFrontedServ(appcfg.FrontedListenAddr, webAddr, &channel, tlsServerAddrs)
}

func startTLSServ(tlsServerMgrCfg *tlsServerMangerConfig) (map[uuid.UUID]string, error) {

	tlsServerAddrs := make(map[uuid.UUID]string, len(*tlsServerMgrCfg.tlsServers))
	for uuid, client := range *tlsServerMgrCfg.tlsServers {
		config := &faketls.Config{Certificates: []faketls.Certificate{client.cert},
			GetFakeCertificate: tlsServerMgrCfg.getFakeCertificate, MaxVersion: tlsServerMgrCfg.maxVersion}
		ln, err := faketls.Listen("tcp", client.listenAddr, config)
		if err != nil {
			fmt.Println(err)
			return nil, err
		}
		tlsServerAddrs[uuid] = client.listenAddr

		go func() {
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					fmt.Println(err)
					continue
				}
				go handleSSLConn(conn)
			}
		}()
	}

	return tlsServerAddrs, nil
}

func forwadTCPConn(remoteAddr string, client net.Conn, data []byte) {
	defer client.Close()

	server, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer server.Close()

	go io.Copy(client, server)
	io.Copy(server, bytes.NewReader(data))
	io.Copy(server, client)
}

func runFrontedServ(frontedAddr, fakeWebAddr string, channel *uuid.UUID, tlsServerAddrs map[uuid.UUID]string) error {
	ln, err := net.Listen("tcp", frontedAddr)
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go handleFrontedConn(conn, fakeWebAddr, channel, tlsServerAddrs)
	}
}

func handleFrontedConn(conn net.Conn, fakeWebAddr string, channel *uuid.UUID, tlsServerAddrs map[uuid.UUID]string) {

	var partClientHello [43]byte
	conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	if _, err := io.ReadFull(conn, partClientHello[:]); err != nil {
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})

	random := partClientHello[11:43]
	clientUUID := crypto.DecodeHelloRandom(random, channel[:])

	addr, ok := tlsServerAddrs[clientUUID]
	if ok {
		go forwadTCPConn(addr, conn, partClientHello[:])

	} else {
		go forwadTCPConn(fakeWebAddr, conn, partClientHello[:])
	}
}

func handleSSLConn(conn net.Conn) {
	defer conn.Close()
	header := make([]byte, proto.HeadLength)
	in := make(chan *proto.Message)
	defer func() {
		close(in)
	}()

	sess := newSession(conn)
	go sess.agent(in)

	for {
		_, err := io.ReadFull(conn, header[:])
		if err != nil {
			return
		}
		message := &proto.Message{}
		Head := &message.Head
		Head.Decode(header[:])

		if Head.BodyLength > 0 {
			if Head.BodyLength > proto.MaxMessageBodySize {
				return
			}
			message.Body = make([]byte, Head.BodyLength)
			_, err = io.ReadFull(conn, message.Body[0:Head.BodyLength])
			if err != nil {
				return
			}
		}

		select {
		case in <- message:
		case <-sess.Die:
			return
		}
	}
}
