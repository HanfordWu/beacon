package beacon

import (
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

	if !expected.Equal(actual) {
		t.Errorf("%s was parsed to %s, but expected %s", ipString, actual, expected)
	}
}
