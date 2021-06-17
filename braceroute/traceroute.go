package main

import (
	"github.com/trstruth/beacon"
)

// Traceroute performs traditional traceroute
func Traceroute(destIP string, sourceIP string, timeout int32, interfaceDevice string) error {

	timeoutInt := int(timeout)

	_, err := beacon.Traceroute(destIP, sourceIP, timeoutInt, interfaceDevice)

	return err
}
