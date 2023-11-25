package tracer

import (
	"encoding/binary"
	"net"
	"os"
	"unicode"
)

func BtfAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf")
	return err == nil
}

func Int2IP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

func Clean(str string) string {
	var res string
	for _, c := range str {
		if unicode.IsPrint(c) && c != 0 {
			res += string(c)
		}
	}
	return res
}
