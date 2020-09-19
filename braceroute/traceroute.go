package main

import (
	"fmt"

	"github.com/trstruth/beacon"
)

// Traceroute performs traditional traceroute
func Traceroute(destIP string, sourceIP string, timeout int32, interfaceDevice string) error {

	timeoutInt := int(timeout)

	response, err := beacon.Traceroute(destIP, sourceIP, timeoutInt, interfaceDevice)
	if err != nil {
		return err
	}

	fmt.Println(response)

	return nil
}
