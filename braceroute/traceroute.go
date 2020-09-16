package main

import (
	"fmt"

	"github.com/trstruth/beacon"
)

// Traceroute performs traditional traceroute
func Traceroute(destIP string, sourceIP string, timeout int32, interfaceDevice string) error {

	response, err := beacon.Traceroute(destIP, sourceIP, timeout, interfaceDevice)
	if err != nil {
		return err
	}

	fmt.Println(response)

	return nil
}
