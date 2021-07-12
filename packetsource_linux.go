package beacon

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func CreatePacketSource(handle *pcap.Handle) *gopacket.PacketSource {
	return gopacket.NewPacketSource(handle, handle.LinkType())
}
