package main

import (
	"testing"
	"net"
	"syreclabs.com/go/faker"
)

func TestParsing(t *testing.T){
	setEndianness()
	for i := 0; i < 100; i++ {
		ip := faker.Internet().IpV4Address()
		t.Logf("Checking %s\n",ip)
		if ip2int(net.ParseIP(ip)) != ParseIPv4ToUint32(ip){
			t.Fatalf("Error! expect %v but got %v",ip2int(net.ParseIP(ip)),ParseIPv4ToUint32(ip))
		}
	}

	t.Logf("%v", int2ip(20490432))
}