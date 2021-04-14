package beacon

const (
	ipHeaderLen   = 20
	icmpHeaderLen = 8
	udpHeaderLen  = 8

	icmpTTLExceeded     = 2816
	icmpEchoRequest     = 2048
	icmpEchoReply       = 0
	icmpPortUnreachable = 771

	maxPortOffset = 89

	boomerangSigV4 = "0x6d"
	boomerangSigV6 = "0x6d6f6279"
)
