// Copyright 2021 Juniper Networks, Inc. All rights reserved.
// Licensed under the Juniper Networks Script Software License (the "License").
// You may not use this script file except in compliance with the License, which is located at
// http://www.juniper.net/support/legal/scriptlicense/
// Unless required by applicable law or otherwise agreed to in writing by the parties,
// software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// juniperLayer.go
// Author: Blaine Williams (blainew@juniper.net)
//
// This Go package decides Juniper TLV headers from the internal network on Junos devices

package beacon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	JuniperFlagPacketIn   = 1 << iota // 0000001
	JuniperFlagNoL2                   // 0000010
	_                                 // 0000100
	_                                 // 0001000
	_                                 // 0010000
	_                                 // 0100000
	JuniperFlagExtensions             // 1000000
)

const (
	juniperNextLayerUnknown  = 0
	juniperNextLayerEthernet = 1
	juniperNextLayerIPv4     = 2
	juniperNextLayerIPv6     = 6
)

const (
	_ = iota
	JuniperExtTLVIFDIndex
	JuniperExtTLVIFDName
	JuniperExtTLVIFDMediaType
	JuniperExtTLVIFLIndex
	JuniperExtTLVIFLUnit
	JuniperExtTLVIFLEncaps
	JuniperExtTLVTTPIFDMediaType
	JuniperExtTLVTTPIFLEncaps
)

var ExtStrings = map[uint8]string{
	JuniperExtTLVIFDIndex:        "Device Interface Index",
	JuniperExtTLVIFDName:         "Device Interface Name",
	JuniperExtTLVIFDMediaType:    "Device Media Type",
	JuniperExtTLVIFLIndex:        "Logical Interface Index",
	JuniperExtTLVIFLUnit:         "Logical Unit Number",
	JuniperExtTLVIFLEncaps:       "Logical Interface Encapsulation",
	JuniperExtTLVTTPIFDMediaType: "TTP derived Device Media Type",
	JuniperExtTLVTTPIFLEncaps:    "TTP derived Logical Interface Encapsulation",
}

const (
	_ = iota
	_
	JuniperIFLEATMSNAP
	JuniperIFLEATMNlpid
	JuniperIFLEATMVcmux
	JuniperIFLEATMLlc
	JuniperIFLEATMPPPVcmux
	JuniperIFLEATMPPPLlc
	JuniperIFLEATMPPPFuni
	JuniperIFLEATMCCC
	JuniperIFLEFrNlpid
	JuniperIFLEFrSNAP
	JuniperIFLEFrPPP
	JuniperIFLEFrCCC
	JuniperIFLEEnet
	JuniperIFLEIEEESNAP
	JuniperIFLEIEEELlc
	JuniperIFLEPPP
	JuniperIFLECiscoHDLC
	JuniperIFLEPPPCCC
	JuniperIFLEIPIPNull
	JuniperIFLEPIMNull
	JuniperIFLEGRENull
	JuniperIFLEGREPPP
	JuniperIFLEPIMdDecaps
	JuniperIFLECiscoHDLCCCc
	JuniperIFLEATMCiscoNlpid
	JuniperIFLEVLANCCC
	JuniperIFLEMLPPP
	JuniperIFLEMLFR
	JuniperIFLELSINull
	JuniperIFLEAggregateUnused
	JuniperIFLEATMCellrelayCCC
	JuniperIFLECrypto
	JuniperIFLEGGSN
	JuniperIFLEATMTCC
	JuniperIFLEFRTCC
	JuniperIFLEPPPTCC
	JuniperIFLECiscoHDLCTCC
	JuniperIFLEEthernetCCC
	JuniperIFLEVT
	JuniperIFLEATMEoALLC
	JuniperIFLEExtendedVLANCCC
	JuniperIFLEATMSNAPTCC
	JuniperIFLEMonitor
	JuniperIFLEEthernetTCC
	JuniperIFLEVLANTCC
	JuniperIFLEExtendedVLANTCC
	JuniperIFLEMFR
	JuniperIFLEEthernetVPLS
	JuniperIFLEEthernetVLANVPLS
	JuniperIFLEEthernetExtendedVLANVPLS
	JuniperIFLEServices
	JuniperIFLEATMEtherVPLSATMLlc
	JuniperIFLEFrPortCCC
	JuniperIFLEATMMLPPPLLC
	JuniperIFLEATMEoACCC
	JuniperIFLELTVLAN
	JuniperIFLECollector
	JuniperIFLEAggregator
	JuniperIFLELAPD
	JuniperIFLEATMPPPoELLC
	JuniperIFLEEthernetPPPoE
	JuniperIFLEPPPoE
	JuniperIFLEPPPSubordinate
	JuniperIFLECiscoHDLCSubordinate
	JuniperIFLEDFC
	JuniperIFLEPICPeer
)

var ExtIFLEStrings = map[uint8]string{
	JuniperIFLEATMSNAP:                  "ATM SNAP",
	JuniperIFLEATMNlpid:                 "ATM NLPID",
	JuniperIFLEATMVcmux:                 "ATM VCMUX",
	JuniperIFLEATMLlc:                   "ATM LLC",
	JuniperIFLEATMPPPVcmux:              "PPP over ATM VCMUX",
	JuniperIFLEATMPPPLlc:                "PPP over ATM LLC",
	JuniperIFLEATMPPPFuni:               "PPP over FUNI",
	JuniperIFLEATMCCC:                   "CCC over ATM",
	JuniperIFLEFrNlpid:                  "FR NLPID",
	JuniperIFLEFrSNAP:                   "FR SNAP",
	JuniperIFLEFrPPP:                    "FR PPP",
	JuniperIFLEFrCCC:                    "FR CCC",
	JuniperIFLEEnet:                     "Ethernet",
	JuniperIFLEIEEESNAP:                 "802.3 SNAP",
	JuniperIFLEIEEELlc:                  "802.3 LLC",
	JuniperIFLEPPP:                      "PPP",
	JuniperIFLECiscoHDLC:                "C-HDLC",
	JuniperIFLEPPPCCC:                   "PPP CCC",
	JuniperIFLEIPIPNull:                 "IPIP",
	JuniperIFLEPIMNull:                  "PIM Null",
	JuniperIFLEGRENull:                  "DFE",
	JuniperIFLEGREPPP:                   "PPP over GRE",
	JuniperIFLEPIMdDecaps:               "PIMd",
	JuniperIFLECiscoHDLCCCc:             "C-HDLC CCC",
	JuniperIFLEATMCiscoNlpid:            "CISCO compatible NLPID",
	JuniperIFLEVLANCCC:                  "VLAN CCC",
	JuniperIFLEMLPPP:                    "MLPPP",
	JuniperIFLEMLFR:                     "MLFR",
	JuniperIFLELSINull:                  "LSI Null",
	JuniperIFLEAggregateUnused:          "Aggregate Unused",
	JuniperIFLEATMCellrelayCCC:          "ATM CCC Cell Relay",
	JuniperIFLECrypto:                   "Crypto",
	JuniperIFLEGGSN:                     "GGSN",
	JuniperIFLEATMTCC:                   "ATM VCMUX TCC",
	JuniperIFLEFRTCC:                    "FR TCC",
	JuniperIFLEPPPTCC:                   "PPP TCC",
	JuniperIFLECiscoHDLCTCC:             "C-HDLC TCC",
	JuniperIFLEEthernetCCC:              "Ethernet CCC",
	JuniperIFLEVT:                       "VT",
	JuniperIFLEATMEoALLC:                "Ethernet over ATM LLC",
	JuniperIFLEExtendedVLANCCC:          "Extended VLAN CCC",
	JuniperIFLEATMSNAPTCC:               "ATM SNAP TCC",
	JuniperIFLEMonitor:                  "Monitor",
	JuniperIFLEEthernetTCC:              "Ethernet TCC",
	JuniperIFLEVLANTCC:                  "VLAN TCC",
	JuniperIFLEExtendedVLANTCC:          "Extended VLAN TCC",
	JuniperIFLEMFR:                      "MFR",
	JuniperIFLEEthernetVPLS:             "VPLS",
	JuniperIFLEEthernetVLANVPLS:         "VLAN VPLS",
	JuniperIFLEEthernetExtendedVLANVPLS: "Extended VLAN VPLS",
	JuniperIFLEServices:                 "Services",
	JuniperIFLEATMEtherVPLSATMLlc:       "Ethernet VPLS over ATM LLC",
	JuniperIFLEFrPortCCC:                "FR CCC",
	JuniperIFLEATMMLPPPLLC:              "MLPPP over ATM LLC",
	JuniperIFLEATMEoACCC:                "Ethernet over ATM CCC",
	JuniperIFLELTVLAN:                   "LT VLAN",
	JuniperIFLECollector:                "Collector",
	JuniperIFLEAggregator:               "Aggregator",
	JuniperIFLELAPD:                     "LAPD",
	JuniperIFLEATMPPPoELLC:              "PPPoE over ATM LLC",
	JuniperIFLEEthernetPPPoE:            "PPP over Ethernet",
	JuniperIFLEPPPoE:                    "PPP over Ethernet",
	JuniperIFLEPPPSubordinate:           "PPP Subordinate",
	JuniperIFLECiscoHDLCSubordinate:     "Cisco HDLC Subordinate",
	JuniperIFLEDFC:                      "Dynamic Flow Collection",
	JuniperIFLEPICPeer:                  "PIC Peer",
}

const (
	_ = iota
	JuniperExtIFMLEther
	JuniperExtIFMLFDDI
	JuniperExtIFMLTokenring
	JuniperExtIFMLPPP
	JuniperExtIFMLFramerelay
	JuniperExtIFMLCiscoHDLC
	JuniperExtIFMLSmdsdxi
	JuniperExtIFMLATMPVC
	JuniperExtIFMLPPPCCC
	JuniperExtIFMLFramerelayCCC
	JuniperExtIFMLIPIP
	JuniperExtIFMLGRE
	JuniperExtIFMLPIM
	JuniperExtIFMLPIMd
	JuniperExtIFMLCiscoHDLCCCC
	JuniperExtIFMLVLANCCC
	JuniperExtIFMLMLPPP
	JuniperExtIFMLMLFR
	JuniperExtIFMLML
	JuniperExtIFMLLSI
	JuniperExtIFMLDFE
	JuniperExtIFMLATMCellrelayCCC
	JuniperExtIFMLCrypto
	JuniperExtIFMLGGSN
	JuniperExtIFMLLSIPPP
	JuniperExtIFMLLSICiscoHDLC
	JuniperExtIFMLPPPTCC
	JuniperExtIFMLFramerelayTCC
	JuniperExtIFMLCiscoHDLCTCC
	JuniperExtIFMLEthernetCCC
	JuniperExtIFMLVT
	JuniperExtIFMLExtendedVLANCCC
	JuniperExtIFMLEtherOverATM
	JuniperExtIFMLMonitor
	JuniperExtIFMLEthernetTCC
	JuniperExtIFMLVLANTCC
	JuniperExtIFMLExtendedVLANTCC
	JuniperExtIFMLController
	JuniperExtIFMLMFR
	JuniperExtIFMLLS
	JuniperExtIFMLEthernetVPLS
	JuniperExtIFMLEthernetVLANVPLS
	JuniperExtIFMLEthernetExtendedVLANVPLS
	JuniperExtIFMLLT
	JuniperExtIFMLServices
	JuniperExtIFMLEtherVPLSOverATM
	JuniperExtIFMLFrPortCCC
	JuniperExtIFMLFramerelayExtCCC
	JuniperExtIFMLFramerelayExtTCC
	JuniperExtIFMLFramerelayFlex
	JuniperExtIFMLGGSNi
	JuniperExtIFMLEthernetFlex
	JuniperExtIFMLCollector
	JuniperExtIFMLAggregator
	JuniperExtIFMLLAPD
	JuniperExtIFMLPPPoE
	JuniperExtIFMLPPPSubordinate
	JuniperExtIFMLCiscoHDLCSubordinate
	JuniperExtIFMLDFC
	JuniperExtIFMLPICPeer
)

var ExtIFMLStrings = map[uint8]string{
	JuniperExtIFMLEther:                    "Ethernet",
	JuniperExtIFMLFDDI:                     "FDDI",
	JuniperExtIFMLTokenring:                "Token Ring",
	JuniperExtIFMLPPP:                      "PPP",
	JuniperExtIFMLFramerelay:               "Frame Relay",
	JuniperExtIFMLCiscoHDLC:                "Cisco HDLC",
	JuniperExtIFMLSmdsdxi:                  "SMDS-DXI",
	JuniperExtIFMLATMPVC:                   "ATM PVC",
	JuniperExtIFMLPPPCCC:                   "PPP CCC",
	JuniperExtIFMLFramerelayCCC:            "Frame Relay CCC",
	JuniperExtIFMLIPIP:                     "IP-IP",
	JuniperExtIFMLGRE:                      "GRE",
	JuniperExtIFMLPIM:                      "PIM Encapsulator",
	JuniperExtIFMLPIMd:                     "PIM Decapsulator",
	JuniperExtIFMLCiscoHDLCCCC:             "Cisco HDLC CCC",
	JuniperExtIFMLVLANCCC:                  "VLAN CCC",
	JuniperExtIFMLMLPPP:                    "Multilink PPP",
	JuniperExtIFMLMLFR:                     "Multilink Frame Relay",
	JuniperExtIFMLML:                       "Multilink",
	JuniperExtIFMLLSI:                      "LSI",
	JuniperExtIFMLDFE:                      "DFE",
	JuniperExtIFMLATMCellrelayCCC:          "ATM Cell Relay CCC",
	JuniperExtIFMLCrypto:                   "IPSEC over IP",
	JuniperExtIFMLGGSN:                     "GGSN",
	JuniperExtIFMLLSIPPP:                   "Link Service - PPP",
	JuniperExtIFMLLSICiscoHDLC:             "Link Sevice - Cisco HDLC",
	JuniperExtIFMLPPPTCC:                   "PPP TCC",
	JuniperExtIFMLFramerelayTCC:            "Frame Relay TCC",
	JuniperExtIFMLCiscoHDLCTCC:             "Cisco HDLC TCC",
	JuniperExtIFMLEthernetCCC:              "Ethernet TCC",
	JuniperExtIFMLVT:                       "VPN Loopback Tunnel",
	JuniperExtIFMLExtendedVLANCCC:          "Extended VLAN TCC",
	JuniperExtIFMLEtherOverATM:             "Ethernet Over ATM",
	JuniperExtIFMLMonitor:                  "Monitor",
	JuniperExtIFMLEthernetTCC:              "Ethernet TCC",
	JuniperExtIFMLVLANTCC:                  "VLAN TCC",
	JuniperExtIFMLExtendedVLANTCC:          "Extended VLAN TCC",
	JuniperExtIFMLController:               "Controller",
	JuniperExtIFMLMFR:                      "Multilink FR UNI-NNI",
	JuniperExtIFMLLS:                       "Link Service",
	JuniperExtIFMLEthernetVPLS:             "Ethernet VPLS",
	JuniperExtIFMLEthernetVLANVPLS:         "VLAN VPLS",
	JuniperExtIFMLEthernetExtendedVLANVPLS: "Extended VLAN VPLS",
	JuniperExtIFMLLT:                       "Logical Tunnel",
	JuniperExtIFMLServices:                 "General Services",
	JuniperExtIFMLEtherVPLSOverATM:         "VPLS Over ATM",
	JuniperExtIFMLFrPortCCC:                "Frame Relay CCC",
	JuniperExtIFMLFramerelayExtCCC:         "Extended Frame Relay CCC",
	JuniperExtIFMLFramerelayExtTCC:         "Extended Frame Relay TCC",
	JuniperExtIFMLFramerelayFlex:           "Flexible Frame Relay",
	JuniperExtIFMLGGSNi:                    "GGSN-I",
	JuniperExtIFMLEthernetFlex:             "Flexible Ethernet Services",
	JuniperExtIFMLCollector:                "Flow Collection",
	JuniperExtIFMLAggregator:               "Aggregator",
	JuniperExtIFMLLAPD:                     "LAPD",
	JuniperExtIFMLPPPoE:                    "PPP over Ethernet",
	JuniperExtIFMLPPPSubordinate:           "PPP Subordinate",
	JuniperExtIFMLCiscoHDLCSubordinate:     "Cisco HDLC Subordinate",
	JuniperExtIFMLDFC:                      "Dynamic Flow Capture",
	JuniperExtIFMLPICPeer:                  "PIC Peer",
}

type JuniperLayer struct {
	layers.BaseLayer
	MagicBytes     []byte
	FlagPacketIn   bool
	FlagNoL2       bool
	FlagExtensions bool
	TLVLength      uint16
	TLVs           []JuniperTLV
	NextHeader     uint8
}

type JuniperTLV struct {
	Type   uint8
	Length uint8
	Value  []byte
	//Description		string
	//ValueStr		string
}

const JuniperLayerName = "Juniper"

var JuniperLayerType = gopacket.RegisterLayerType(
	26361,
	gopacket.LayerTypeMetadata{
		JuniperLayerName,
		gopacket.DecodeFunc(decodeJuniperLayer),
	},
)

func (j *JuniperLayer) LayerType() gopacket.LayerType {
	return JuniperLayerType
}

func (j *JuniperLayer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		df.SetTruncated()
		return fmt.Errorf("Invalid JuniperTLV Header. Length %d < 6", len(data))
	}
	var magicBytes = []byte{byte(0x4d), byte(0x47), byte(0x43)}
	if bytes.Compare(data[0:3], magicBytes) != 0 {
		return fmt.Errorf("Incorrect MagicBytes 0x%06x != 0x4d4743", j.MagicBytes)
	}
	j.MagicBytes = data[0:3]
	j.FlagPacketIn = (data[3] & JuniperFlagPacketIn) == JuniperFlagPacketIn
	j.FlagNoL2 = (data[3] & JuniperFlagNoL2) == JuniperFlagNoL2
	j.FlagExtensions = (data[3] & JuniperFlagExtensions) == JuniperFlagExtensions
	j.TLVLength = binary.BigEndian.Uint16(data[4:6])
	headerLength := 6 + j.TLVLength
	if uint16(len(data)) < headerLength {
		df.SetTruncated()
		return fmt.Errorf("Invalid JuniperTLV Header. Length %d < %d", len(data), headerLength)
	}

	for tlvData := data[6:headerLength]; len(tlvData) > 0; {
		tlv, err := decodeJuniperTLV(tlvData)
		if err != nil {
			df.SetTruncated()
			return err
		}
		j.TLVs = append(j.TLVs, *tlv)
		if tlv.Length <= 0 {
			return fmt.Errorf("TLV Length <= 0")
		}
		// Skip to the next TLV
		tlvData = tlvData[2+tlv.Length:]
	}

	if j.FlagNoL2 {
		if uint16(len(data)) < headerLength+4 {
			df.SetTruncated()
			return fmt.Errorf("No L2 Flag is set, but there is no payload: %d < %d", len(data), headerLength+1)
		}
		j.NextHeader = data[headerLength]
		headerLength += 4
	} else {
		// Assume all L2 headers are Ethernet
		j.NextHeader = juniperNextLayerEthernet
	}

	j.BaseLayer = layers.BaseLayer{data[:headerLength], data[headerLength:]}
	return nil
}

func (j *JuniperLayer) NextLayerType() gopacket.LayerType {
	// Assume Ethernet header next for now
	switch j.NextHeader {
	case juniperNextLayerIPv6:
		return layers.LayerTypeIPv6
	case juniperNextLayerIPv4:
		return layers.LayerTypeIPv4
	case juniperNextLayerEthernet:
		return layers.LayerTypeEthernet
	}
	// The layer type is unknown, it will be incorrectly decoded
	return layers.LayerTypeEthernet
}

func (j *JuniperLayer) CanDecode() gopacket.LayerClass {
	return JuniperLayerType
}

// This one hasn't been tested yet
func (j *JuniperLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	headerBytes, err := b.PrependBytes(int(6 + j.TLVLength))
	if err != nil {
		return err
	}

	var magicBytes = []byte{byte(0x4d), byte(0x47), byte(0x43)}
	copy(headerBytes, magicBytes)
	var flags = byte(0x0)
	if j.FlagPacketIn {
		flags |= JuniperFlagPacketIn
	}
	if j.FlagNoL2 {
		flags |= JuniperFlagNoL2
	}
	if j.FlagExtensions {
		flags |= JuniperFlagExtensions
	}
	headerBytes[3] = flags
	binary.BigEndian.PutUint16(headerBytes[4:], j.TLVLength)
	var index uint16 = 6
	for _, tlv := range j.TLVs {
		if len(headerBytes[index:]) < int(2+tlv.Length) {
			return fmt.Errorf("Header is too small for TLVs: %d < %d", len(headerBytes[index:]), 2+tlv.Length)
		}
		headerBytes[index] = tlv.Type
		headerBytes[index+1] = tlv.Length
		copy(headerBytes[index+2:], tlv.Value)
		index += uint16(tlv.Length)
	}
	if index < 6+j.TLVLength {
		return fmt.Errorf("Header length is larger than the total TLV size: %d < %d", index, j.TLVLength)
	}
	return nil
}

func decodeJuniperLayer(data []byte, p gopacket.PacketBuilder) error {
	juniperTLV := &JuniperLayer{}
	if err := juniperTLV.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(juniperTLV)
	return p.NextDecoder(juniperTLV.NextLayerType())
}

func decodeJuniperTLV(data []byte) (*JuniperTLV, error) {
	t := &JuniperTLV{}
	t.Type = data[0]
	//t.Description = ExtStrings[t.Type]
	t.Length = data[1]
	if uint8(len(data)) < t.Length+2 {
		return t, fmt.Errorf("TLV Length >= data size")
	}
	// Value is the rest of the TLV data
	t.Value = data[2 : 2+t.Length]
	//switch t.Type {
	//case JuniperExtTLVIFDMediaType:
	//	t.ValueStr = ExtIFMLStrings[uint8(t.Value[0])]
	//case JuniperExtTLVIFLEncaps:
	//	t.ValueStr = ExtIFLEStrings[uint8(t.Value[0])]
	//}
	return t, nil
}
