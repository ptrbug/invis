package proto

import (
	"errors"
	"fmt"
	"net"
)

//AddressType socks5 address type
type AddressType byte

const (
	IPv4       AddressType = 1
	DOMAINNAME AddressType = 3
	IPv6       AddressType = 4
)

//SOCKS5Address socks5 address
type SOCKS5Address struct {
	AddressType AddressType
	Address     string
	Port        uint16
}

//Encode convert SOCKS5Address to bytes
func (addr *SOCKS5Address) Encode(data []byte) (length int, err error) {

	l := len(data)
	if l >= 1 {
		data[0] = byte(addr.AddressType)
		if addr.AddressType == IPv4 && l >= 7 {
			copy(data[1:5], []byte(net.ParseIP(addr.Address).To4()))
			data[5] = byte(addr.Port >> 8)
			data[6] = byte(addr.Port & 0xff)
			return 7, nil
		} else if addr.AddressType == IPv6 && l >= 19 {
			copy(data[1:17], []byte(net.ParseIP(addr.Address).To16()))
			data[17] = byte(addr.Port >> 8)
			data[18] = byte(addr.Port & 0xff)
			return 19, nil
		} else if addr.AddressType == DOMAINNAME && l >= 2 {
			addrLen := len(addr.Address)
			if addrLen <= 255 {
				data[1] = byte(addrLen)
				if addrLen > 0 && l >= 4+addrLen {
					copy(data[2:2+addrLen], []byte(addr.Address))
					data[2+addrLen] = byte(addr.Port >> 8)
					data[3+addrLen] = byte(addr.Port & 0xff)
					return 4 + addrLen, nil
				}
			}
		}
	}
	return 0, errors.New("socks5 address encode error")
}

//Decode convert bytes to SOCKS5Address
func (addr *SOCKS5Address) Decode(data []byte) (length int, err error) {
	l := len(data)
	if l >= 1 {
		addr.AddressType = AddressType(data[0])
		if addr.AddressType == IPv4 && l >= 7 {
			addr.Address = net.IP(data[1:5]).String()
			addr.Port = (uint16(data[5]) << 8) | uint16(data[6])
			return 7, nil
		} else if addr.AddressType == IPv6 && l >= 19 {
			addr.Address = net.IP(data[1:17]).String()
			addr.Port = (uint16(data[17]) << 8) | uint16(data[18])
			return 19, nil
		} else if addr.AddressType == DOMAINNAME && l >= 2 {
			addrLen := int(data[1])
			if addrLen > 0 && l >= 4+addrLen {
				addr.Address = string(data[2 : 2+addrLen])
				addr.Port = (uint16(data[2+addrLen]) << 8) | uint16(data[3+addrLen])
				return 4 + addrLen, nil
			}
		}
	}
	return 0, errors.New("socks5 address decode error")
}

func (addr *SOCKS5Address) String() string {
	return fmt.Sprintf("%s:%d", addr.Address, addr.Port)
}
