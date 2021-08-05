package main

import (
	"net"
	"encoding/binary"
	"unsafe"
	"fmt"
)

// Bigger than we need, not too big to worry about overflow
const big = 0xFFFFFF

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return nativeEndian.Uint32(ip[12:16])
	}
	return nativeEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	nativeEndian.PutUint32(ip, nn)
	return ip
}

// Decimal to integer.
// Returns number, characters consumed, success.
func dtoi(s string) (n int, i int, ok bool) {
	n = 0
	for i = 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= big {
			return big, i, false
		}
	}
	if i == 0 {
		return 0, 0, false
	}
	return n, i, true
}

// ParseIPv4ToUint32 Parse IPv4 address (d.d.d.d) to uint32.
func ParseIPv4ToUint32(s string) uint32 {
	var p [net.IPv4len]byte
	for i := 0; i < net.IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return 0
		}
		if i > 0 {
			if s[0] != '.' {
				return 0
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)
		if !ok || n > 0xFF {
			return 0
		}
		s = s[c:]
		p[i] = byte(n)
	}
	if len(s) != 0 {
		return 0
	}
	return nativeEndian.Uint32(p[:4])
}

func setEndianness(){
	endtest := [2]byte{}
    *(*uint16)(unsafe.Pointer(&endtest[0])) = uint16(0xABCD)

    switch endtest {
    case [2]byte{0xCD, 0xAB}:
    	fmt.Println("Set to LittleEndian")
        nativeEndian = binary.LittleEndian
    case [2]byte{0xAB, 0xCD}:
    	fmt.Println("Set to BigEndian")
        nativeEndian = binary.BigEndian
    default:
        panic("Could not determine native endianness.")
    }
}