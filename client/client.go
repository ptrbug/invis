package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"

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
		conn, err := l.Accept()
		if err != nil {
			loger.Fatal(err)
		}
		go handleClientRequest(conn)
	}
}

func handleClientRequest(conn net.Conn) {
	firstPacket := make([]byte, proto.MaxMessageSize)
	firstPacketLength, err := conn.Read(firstPacket[proto.HeadLength:])
	if err != nil {
		return
	}

	if firstPacket[proto.HeadLength] == 5 && firstPacketLength >= 3 {
		handleSocks5Request(conn, firstPacket, firstPacketLength)

	} else {
		handleHTTPRequest(conn, firstPacket, firstPacketLength)
	}
}
