package crypto

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

//NewEncodeHelloRandomFunc bind args
func NewEncodeHelloRandomFunc(channelUUID, clientUUID []byte) func(random []byte, r io.Reader) error {
	return func(random []byte, r io.Reader) error {
		return EncodeHelloRandom(random, r, channelUUID, clientUUID)
	}
}

//EncodeHelloRandom encode client hello random
func EncodeHelloRandom(random []byte, r io.Reader, channelUUID, clientUUID []byte) error {

	binary.LittleEndian.PutUint32(random[0:4], uint32(time.Now().Unix()))
	_, err := io.ReadFull(r, random[4:16])
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	origin := random[16:32]
	copy(origin, clientUUID)
	key := random[4:16]
	for i := 0; i < len(origin); i++ {
		origin[i] ^= key[i%(len(key))]
	}
	encrypted := AesEncryptCBC(origin, channelUUID)
	copy(random[16:32], encrypted)
	return nil
}

//DecodeHelloRandom decode client hello random
func DecodeHelloRandom(random []byte, channelUUID []byte) (clientUUID uuid.UUID) {

	decrypted := AesDecryptCBC(random[16:32], channelUUID)
	key := random[4:16]
	for i := 0; i < len(decrypted); i++ {
		decrypted[i] ^= key[i%(len(key))]
	}
	copy(clientUUID[:], decrypted)
	return clientUUID
}
