package main

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "net"
    "time"
    "fmt"
    "golang.org/x/net/ipv6"
    "os"
    "syscall"
    "strings"
)

var (
    snapshot_len int32  = 2048 //os.Getenv("snapshot_len")
    promiscuous  bool   = true //os.Getenv("promisuous")
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
    buffer       gopacket.SerializeBuffer
    options      gopacket.SerializeOptions
)

func send_packet_syscall(packetData []byte, dst_ip string){
    fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
    if err != nil {
        fmt.Println("error creating raw syscall socket")
        log.Fatal(err)
    }
    dstIPAddr := net.ParseIP(dst_ip)
    dst_addr_16 := dstIPAddr.To16()
    fmt.Println("dst_addr_16: ", dst_addr_16)
    inet6_addr := syscall.SockaddrInet6{
        //Port: 25305,
        Addr: [16]byte{dst_addr_16[0], dst_addr_16[1], dst_addr_16[2], dst_addr_16[3], dst_addr_16[4], dst_addr_16[5], dst_addr_16[6], dst_addr_16[7], dst_addr_16[8], dst_addr_16[9], dst_addr_16[10], dst_addr_16[11], dst_addr_16[12], dst_addr_16[13], dst_addr_16[14], dst_addr_16[15]},
        //ZoneId: 32,
    }
    err = syscall.Sendto(fd, packetData, 0, &inet6_addr)
    if err != nil {
        fmt.Println("error in sendto syscall")
        log.Fatal(err)
    }
    fmt.Println("finished writing packet syscall")
    return
}

func send_packet_pcap(packetData []byte, src_device string, snapshot_len int32, promiscuous bool, timeout time.Duration){
    write_handle, err := pcap.OpenLive(src_device, snapshot_len, promiscuous, timeout)
    //err = write_handle.SetLinkType(layers.LinkTypeIPv6)
    //if err != nil {
    //    fmt.Println("couldnt change linktype")
    //    log.Fatal(err)
    //}
    //fmt.Println("write handle link type: ", write_handle.LinkType())
    //if err != nil { log.Fatal(err) }
    defer write_handle.Close()

    err = write_handle.WritePacketData(packetData)
    if err != nil {
        fmt.Println("error in write data")
        log.Fatal(err)
    }

    fmt.Println("finished writing packet pcap")
    return
}

func send_packet_net(packetData []byte, protocol, src_ip, dst_ip string){
    dstIPAddr := net.ParseIP(dst_ip)
    c, err := net.ListenPacket(protocol, src_ip)
    if err != nil {
        fmt.Println("err in net.ListenPacket")
        log.Fatal(err)
    }
    defer c.Close()
    p := ipv6.NewPacketConn(c)
    dstIP := net.IPAddr{IP: dstIPAddr}
    p.WriteTo(packetData, &ipv6.ControlMessage{}, &dstIP)

    fmt.Println("finished writing packet net.ipv6")
    return
}

func craft_ipip_v6_packet(src_mac, nxt_mac string, path []string, include_eth bool) []byte {
    opts := gopacket.SerializeOptions{
        ComputeChecksums: true,
        FixLengths:true,
    }
    buf := gopacket.NewSerializeBuffer()
    num_layers := len(path) + 2
    packet_layers := make([]gopacket.SerializableLayer, num_layers)

    for idx := range path[:len(path) - 1] {
        addressStart := net.ParseIP(path[idx])
        addressEnd := net.ParseIP(path[idx+1])

        fmt.Println("start: ", addressStart)
        fmt.Println("end: ", addressEnd)

        v6_encapped := layers.IPv6{
            Version: uint8(6),
            HopLimit: uint8(64),
            SrcIP: addressStart,
            DstIP: addressEnd,
            NextHeader: layers.IPProtocolIPv6,
            FlowLabel: uint32(0),
            TrafficClass: uint8(0),
        }
        packet_layers[idx] = &v6_encapped
    }

    last_v6 := layers.IPv6{
        Version: uint8(6),
        HopLimit: uint8(64),
        SrcIP: net.ParseIP(path[len(path) - 2]),
        DstIP: net.ParseIP(path[len(path) - 1]),
        NextHeader: layers.IPProtocolUDP,
        FlowLabel: uint32(0),
        TrafficClass: uint8(0),
    }

    packet_layers[len(path) - 1] = &last_v6

    srcPort := 26305
    dstPort := 25305
    udpLayer := layers.UDP{
        SrcPort : layers.UDPPort(srcPort),
        DstPort: layers.UDPPort(dstPort),
    }
    udpLayer.SetNetworkLayerForChecksum(&last_v6)

    packet_layers[len(path)] = &udpLayer

    payload := gopacket.Payload([]byte("This is my packet, not your packet, stop reading me!"))
    packet_layers[len(path) + 1] = payload

    fmt.Println(packet_layers)

    err := gopacket.SerializeLayers(buf, opts, packet_layers...)
    if err != nil {
        fmt.Println("failure in serialize ipip layers")
        log.Fatal(err)
    }
    packetData := buf.Bytes()

    return packetData
}

func craft_icmp_packet(src_ip, dst_ip, src_mac, nxt_mac string, include_eth bool, seqNumber uint16) []byte {
    srcIPAddr := net.ParseIP(src_ip)//"fe80::20d:3aff:fef7:d895")
    dstIPAddr := net.ParseIP(dst_ip)
    fmt.Println("dstIPAddr: ", dstIPAddr)
    SrcMacAddr, err := net.ParseMAC(src_mac)
    DstMacAddr, err := net.ParseMAC(nxt_mac)

    payload := gopacket.Payload([]byte(""))
    ethLayer := layers.Ethernet{
        SrcMAC: SrcMacAddr,
        DstMAC: DstMacAddr,
        EthernetType: layers.EthernetTypeIPv6,
    }
    ipV6Layer := layers.IPv6{
        SrcIP: srcIPAddr,
        DstIP: dstIPAddr,
        NextHeader: layers.IPProtocolICMPv6,
        HopLimit: uint8(64),
        Version: uint8(6),
    }
    err = ipV6Layer.AddressTo16()
    if err != nil {
        fmt.Println("couldn't resolve src or dst ip address for ipv6 layer")
        log.Fatal(err)
    }
    icmpLayer := layers.ICMPv6{
        TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
    }
    icmpLayer.SetNetworkLayerForChecksum(&ipV6Layer)
    icmpEchoLayer := layers.ICMPv6Echo{
        Identifier: uint16(666),
        SeqNumber: seqNumber,
    }
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths: true,
        ComputeChecksums: true,
    }
    var packetData []byte //= make([]byte, snapshot_len)
    if include_eth == true {
        err = gopacket.SerializeLayers(buf, opts, &ethLayer, &ipV6Layer, &icmpLayer, &icmpEchoLayer, payload)
        packetData = buf.Bytes()
    } else {
        err = gopacket.SerializeLayers(buf, opts, &ipV6Layer, &icmpLayer, &icmpEchoLayer, payload)
        packetData = buf.Bytes()
    }
    if err != nil {
        fmt.Println("error in SerializeLayers")
        log.Fatal(err)
    }

    return packetData
}

func craft_udp_packet(src_ip, dst_ip, src_mac, nxt_mac string, include_eth bool) []byte {
    srcIPAddr := net.ParseIP(src_ip)//"fe80::20d:3aff:fef7:d895")
    dstIPAddr := net.ParseIP(dst_ip)
    fmt.Println("dstIPAddr: ", dstIPAddr)
    srcPort := 26305
    dstPort := 25305
    SrcMacAddr, err := net.ParseMAC(src_mac)
    DstMacAddr, err := net.ParseMAC(nxt_mac)

    payload := gopacket.Payload([]byte("This is my packet, not your packet, stop reading me!"))
    ethLayer := layers.Ethernet{
        SrcMAC: SrcMacAddr,
        DstMAC: DstMacAddr,
        EthernetType: layers.EthernetTypeIPv6,
    }
    ipV6Layer := layers.IPv6{
        SrcIP: srcIPAddr,
        DstIP: dstIPAddr,
        NextHeader: layers.IPProtocolUDP,
    }
    err = ipV6Layer.AddressTo16()
    if err != nil {
        fmt.Println("couldn't resolve src or dst ip address for ipv6 layer")
        log.Fatal(err)
    }
    udpLayer := layers.UDP{
        SrcPort: layers.UDPPort(srcPort),
        DstPort: layers.UDPPort(dstPort),
        //Length: uint16(8 + len(payload)),
    }
    udpLayer.SetNetworkLayerForChecksum(&ipV6Layer)
    buf := gopacket.NewSerializeBuffer()
    opts := gopacket.SerializeOptions{
        FixLengths: true,
        ComputeChecksums: true,
    }
    var packetData []byte //= make([]byte, snapshot_len)
    if include_eth == true {
        err = gopacket.SerializeLayers(buf, opts, &ethLayer, &ipV6Layer, &udpLayer, payload)
        packetData = buf.Bytes()
    } else {
        err = gopacket.SerializeLayers(buf, opts, &ipV6Layer, &udpLayer, payload)
        packetData = buf.Bytes()
    }
    if err != nil {
        fmt.Println("error in SerializeLayers")
        log.Fatal(err)
    }

    return packetData
}

func listen_packet(dst_device string, snapshot_len int32, promiscuous bool, timeout time.Duration, filter string, read chan bool) *pcap.Handle{
    listen_handle, err := pcap.OpenLive(dst_device, snapshot_len, promiscuous, timeout)
    listen_handle.SetDirection(pcap.DirectionIn)
    if err != nil { log.Fatal(err) }

    err = listen_handle.SetBPFFilter(filter)
    if err != nil { log.Fatal(err) }

    packetSource := gopacket.NewPacketSource(listen_handle, listen_handle.LinkType())

    go func(ps *gopacket.PacketSource){
         for packet := range ps.Packets() {
             fmt.Println("=======================================================================")
             fmt.Println(packet)

             icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
             if icmpLayer != nil {
                 fmt.Println("ICMP layer detected")
                 icmp, _ := icmpLayer.(*layers.ICMPv6)
                 fmt.Println("icmp code: ", icmp.TypeCode)
             }

             udpLayer := packet.Layer(layers.LayerTypeUDP)
             if udpLayer != nil {
                 fmt.Println("UDP layer detected")
                 udp, _ := udpLayer.(*layers.UDP)
                 fmt.Println("dstPort ", udp.DstPort)
             }

             applicationLayer := packet.ApplicationLayer()
             if applicationLayer != nil {
                 fmt.Println("Application layer detected")
                 fmt.Println("payload: ", string(applicationLayer.Payload()))
             }

             layers := packet.Layers()
             for _, layer := range layers {
                 fmt.Println("PACKET LAYER: ", layer.LayerType())
             }
             fmt.Println("=======================================================================")
             read <- true
         }
    }(packetSource)
    return listen_handle
}

func main() { // src_device, dst_device, src_ip, dst_ip, src_mac, nxt_mac 
    // Open device
    src_device, present := os.LookupEnv("src_device")
    if !present {
        src_device = "lo"
    }
    dst_device, present := os.LookupEnv("dst_device")
    if !present {
        dst_device = "lo"
    }
    src_ip, present := os.LookupEnv("src_ip")
    if !present {
        src_ip = "::1"
    }
    dst_ip, present := os.LookupEnv("dst_ip")
    if !present {
        dst_ip = "::1"
    }
    src_mac, present := os.LookupEnv("src_mac")
    if !present {
        src_mac = "00:00:00:00:00:00"
    }
    nxt_mac, present := os.LookupEnv("nxt_mac")
    if !present {
        nxt_mac = "00:00:00:00:00:00"
    }
    path, present := os.LookupEnv("path")
    if !present {
        path = src_ip + "," +  dst_ip + "," +  src_ip
    }
    boomerangPath := strings.Split(path, ",")
    fmt.Println(boomerangPath)

    fmt.Println(src_device)
    fmt.Println(dst_device)
    fmt.Println(src_ip)
    fmt.Println(dst_ip)
    fmt.Println(src_mac)
    fmt.Println(nxt_mac)

    //var filter string = "udp and port 25305"
    filter := "ip6"
    read := make(chan bool, 1)
    listen_handle := listen_packet(src_device, snapshot_len, promiscuous, timeout, filter, read)
    defer listen_handle.Close()

    //packetDataWithEth := craft_udp_packet(src_ip, dst_ip, src_mac, nxt_mac, true)
    //packet_to_print := gopacket.NewPacket(packetDataWithEth,layers.LayerTypeEthernet,gopacket.Default,)
    //send_packet_pcap(packetDataWithEth, src_device, snapshot_len, promiscuous, timeout)
    //fmt.Println("packetWithEth: ", packet_to_print)

    //packetDataWithoutEth := craft_udp_packet(src_ip, dst_ip, src_mac, nxt_mac, false)
    //packet_to_print := gopacket.NewPacket(packetDataWithoutEth,layers.LayerTypeIPv6,gopacket.Default,)
    //fmt.Println("packetWithoutEth: ", packet_to_print)
    //send_packet_net(packetDataWithoutEth, "ip6:17", "::1", dst_ip)

    //send_packet_syscall(packetDataWithoutEth, dst_ip)

    //icmpDataWithoutEth := craft_icmp_packet(src_ip, dst_ip, src_mac, nxt_mac, false, 1)
    //packet_to_print = gopacket.NewPacket(icmpDataWithoutEth,layers.LayerTypeIPv6,gopacket.Default,)
    //fmt.Println("icmpWithoutEth: ", packet_to_print)
    //send_packet_syscall(icmpDataWithoutEth, dst_ip)

    boomerangPacketData := craft_ipip_v6_packet(src_mac, nxt_mac, boomerangPath, false)
    packet_to_print := gopacket.NewPacket(boomerangPacketData,layers.LayerTypeIPv6,gopacket.Default,)
    fmt.Println("bomerangPacket: ", packet_to_print)
    send_packet_syscall(boomerangPacketData, boomerangPath[1])

    <-read
}
