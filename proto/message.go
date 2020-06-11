package proto

import "encoding/binary"

const (
	HeadLength         = 5
	MaxMessageSize     = 1 << 16
	MaxMessageBodySize = MaxMessageSize - HeadLength
)

type StreamType byte

// Stream types
const (
	STREAM_NEW  StreamType = 0x00
	STREAM_DEL  StreamType = 0x01
	STREAM_DATA StreamType = 0x02
)

type ProtoType byte

//PROTO types
const (
	TCP_PROTO ProtoType = 0x0
	UPD_PROTO ProtoType = 0x1
)

const (
	protoTypeMask  byte = 0x01
	streamTypeMask byte = 0x03
)

//MessageHead the head of Message
type MessageHead struct {
	StreamType StreamType
	ProtoType  ProtoType
	StreamID   uint16
	BodyLength uint16
}

//Encode MessageHead to bytes
func (m *MessageHead) Encode(data []byte) {
	data[0] = ((byte(m.StreamType) & streamTypeMask) << 1) | (byte(m.ProtoType) & protoTypeMask)
	binary.BigEndian.PutUint16(data[1:3], m.StreamID)
	binary.BigEndian.PutUint16(data[3:5], m.BodyLength)
}

//Decode bytes to MessageHead
func (m *MessageHead) Decode(data []byte) {
	m.StreamType = StreamType((data[0] >> 1) & streamTypeMask)
	m.ProtoType = ProtoType(data[0] & protoTypeMask)
	m.StreamID = binary.BigEndian.Uint16(data[1:3])
	m.BodyLength = binary.BigEndian.Uint16(data[3:5])
}

//Message x
type Message struct {
	Head MessageHead
	Body []byte
}
