package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	"github.com/ptrbug/invis/crypto"
	"github.com/ptrbug/invis/proto"
)

type appConfig struct {
	AutoStart     bool
	ListenAddr    string
	ServerAddr    string
	Channel       string
	Client        string
	FakeWebDomain string
}

var loger *log.Logger
var config appConfig
var pool *sessionPool

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		panic(err)
	}
	err = os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	logFile, err := os.OpenFile("log.txt", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.ModePerm)
	if nil != err {
		panic(err)
	}
	loger := log.New(logFile, "", log.Ldate|log.Ltime|log.Lshortfile)

	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		loger.Fatal("config.json reading error", err)
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		loger.Fatal("Unmarshal config.json file error", err)
	}

	channelUUID, err := uuid.Parse(config.Channel)
	if err != nil {
		loger.Fatal("parse channel uuid error", err)
	}

	clientUUID, err := uuid.Parse(config.Client)
	if err != nil {
		loger.Fatal("parse client uuid error", err)
	}

	cert, err := crypto.CreateX509KeyPair(clientUUID[:], 2048)
	if err != nil {
		loger.Fatal("createX509KeyPair error", err)
	}

	setAutoStart(config.AutoStart)

	pool = pool.newSessionPool(config.ServerAddr, config.FakeWebDomain, cert, channelUUID[:], clientUUID[:])
	pool.run()

	l, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		loger.Fatal(err)
	}

	loger.Printf("server started, listen on %v\n", config.ListenAddr)

	for {
		client, err := l.Accept()
		if err != nil {
			loger.Fatal(err)
		}
		go handleHTTPRequest(client)
	}
}

func handleHTTPRequest(conn net.Conn) {
	defer conn.Close()

	var buffer [proto.MaxMessageSize]byte
	n, err := conn.Read(buffer[proto.HeadLength:])
	if err != nil {
		return
	}
	var method, rawurl, host string
	var port int
	index := bytes.IndexByte(buffer[proto.HeadLength:], '\n')
	if index == -1 {
		return
	}
	fmt.Sscanf(string(buffer[proto.HeadLength:]), "%s%s", &method, &rawurl)
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

	err = sess.writeServerStreamNew(host, uint16(port), streamID)
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
		head.BodyLength = uint16(n)
		head.Encode(buffer[0:proto.HeadLength])
		err := sess.writeServer(buffer[:proto.HeadLength+n])
		if err != nil {
			return
		}
	}

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
