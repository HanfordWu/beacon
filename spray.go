package main

import (
	"fmt"
	"net"
)

// Spray sends encapsulated packets over the to/from paths calculated by
// traceroute and reverse traceroute
func Spray(destIP net.IP, tc TransportChannel) error {

	/*
		sourceIP, err := findLocalIP()
		if err != nil {
			return err
		}
	*/

	/*
		pathTo, err := GetPathTo(destIP, tc)
		if err != nil {
			return err
		}
		fmt.Println(pathTo)

		pathFrom, err := GetPathFrom(destIP, tc)
		if err != nil {
			return err
		}
		fmt.Println(pathFrom)
	*/

	sourceIP := net.IP{104, 44, 227, 112}
	pathBetween, err := GetPathFromSourceToDest(sourceIP, destIP, tc)
	if err != nil {
		return err
	}
	fmt.Println(pathBetween)

	return nil
}
