package beacon

import (
	"encoding/hex"
	"net"
	"testing"
)

func TestParseIPFromString(t *testing.T) {
	ipString := "127.0.0.1"

	expected := net.IP{127, 0, 0, 1}
	actual, err := ParseIPFromString(ipString)
	if err != nil {
		t.Errorf("Error parsing ip string: %s", ipString)
		t.FailNow()
	}

	if !expected.Equal(actual) {
		t.Errorf("%s was parsed to %s, but expected %s", ipString, actual, expected)
	}
}

func TestParseIPFromName(t *testing.T) {
	ipString := "localhost"

	expected := net.IP{127, 0, 0, 1}

	actual, err := ParseIPFromString(ipString)
	if err != nil {
		t.Errorf("Error parsing ip string: %s", ipString)
		t.FailNow()
	}

	if actual.Equal(net.IPv6loopback) {
		return
	}

	if !expected.Equal(actual) {
		t.Errorf("%s was parsed to %s, but expected %s", ipString, actual, expected)
	}
}

func TestTracerouteResponseMatchesPortPair(t *testing.T) {
	hexString := "4500002600004000011113ec0d6aeeb1682c019482e182ba0012752f7472616365726f757465"
	payload, err := hex.DecodeString(hexString)
	if err != nil {
		t.Errorf("Failed to parse valid byte array from hex string: %s", hexString)
	}

	ports := portPair{
		src: 33505,
		dst: 33466,
	}

	if !tracerouteResponseMatchesPortPair(payload, ports) {
		t.Errorf("tracerouteResponse ports matched the test input, but the function failed to correctly assess it")
	}
}

func TestInvalidTracerouteResponseMatchesPortPair(t *testing.T) {
	hexString := "4500002600004000011113ec0d6aeeb1682c019482e182ba0012752f7472616365726f757465"
	payload, err := hex.DecodeString(hexString)
	if err != nil {
		t.Errorf("Failed to parse valid byte array from hex string: %s", hexString)
	}

	// ports do not match packet described by hex string
	ports := portPair{
		src: 00001,
		dst: 00001,
	}

	if tracerouteResponseMatchesPortPair(payload, ports) {
		t.Errorf("tracerouteResponse ports didn't match the test input, but the function thought they did")
	}
}
