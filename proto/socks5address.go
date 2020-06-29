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
	FQDN        string
	IP          net.IP
	Port        uint16
}

//Encode convert SOCKS5Address to bytes
func (d *SOCKS5Address) Encode(data []byte) (int, error) {

	l := len(data)
	if l >= 1 {
		data[0] = byte(d.AddressType)
		if d.AddressType == IPv4 && l >= 7 {
			copy(data[1:5], []byte(d.IP.To4()))
			data[5] = byte(d.Port >> 8)
			data[6] = byte(d.Port & 0xff)
			return 7, nil
		} else if d.AddressType == IPv6 && l >= 19 {
			copy(data[1:17], []byte(d.IP.To16()))
			data[17] = byte(d.Port >> 8)
			data[18] = byte(d.Port & 0xff)
			return 19, nil
		} else if d.AddressType == DOMAINNAME && l >= 2 {
			fqdnLen := len(d.FQDN)
			if fqdnLen <= 255 {
				data[1] = byte(fqdnLen)
				if fqdnLen > 0 && l >= 4+fqdnLen {
					copy(data[2:2+fqdnLen], []byte(d.FQDN))
					data[2+fqdnLen] = byte(d.Port >> 8)
					data[3+fqdnLen] = byte(d.Port & 0xff)
					return 4 + fqdnLen, nil
				}
			}
		}
	}
	return 0, errors.New("socks5 address encode error")
}

//Decode convert bytes to SOCKS5Address
func (d *SOCKS5Address) Decode(data []byte) (int, error) {
	l := len(data)
	if l >= 1 {
		d.AddressType = AddressType(data[0])
		if d.AddressType == IPv4 && l >= 7 {
			d.IP = net.IP(data[1:5])
			d.Port = (uint16(data[5]) << 8) | uint16(data[6])
			return 7, nil
		} else if d.AddressType == IPv6 && l >= 19 {
			d.IP = net.IP(data[1:17])
			d.Port = (uint16(data[17]) << 8) | uint16(data[18])
			return 19, nil
		} else if d.AddressType == DOMAINNAME && l >= 2 {
			addrLen := int(data[1])
			if addrLen > 0 && l >= 4+addrLen {
				d.FQDN = string(data[2 : 2+addrLen])
				d.Port = (uint16(data[2+addrLen]) << 8) | uint16(data[3+addrLen])
				return 4 + addrLen, nil
			}
		}
	}
	return 0, errors.New("socks5 address decode error")
}

func (d *SOCKS5Address) String() string {
	var ip string
	if d.AddressType == IPv4 || d.AddressType == IPv6 {
		ip = d.IP.String()
	} else {
		ip = d.FQDN
	}
	return fmt.Sprintf("%s:%d", ip, d.Port)
}
