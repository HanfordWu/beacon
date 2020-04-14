package main

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/trstruth/beacon"

	"github.com/olekukonko/tablewriter"
)

type probeStats struct {
	sync.RWMutex
	path            beacon.Path
	source          string
	dest            string
	hopToIdxMapping map[string]int
	hopStatSlice    []hopStats
	totalPackets    int
	interfaceDevice string
}

func newProbeStats(path beacon.Path, totalPackets int, interfaceDevice string) *probeStats {
	s := probeStats{
		path:            path,
		source:          path[0].String(),
		dest:            path[len(path)-1].String(),
		hopToIdxMapping: make(map[string]int),
		hopStatSlice:    make([]hopStats, len(path)-1),
		totalPackets:    totalPackets,
		interfaceDevice: interfaceDevice,
	}

	for idx, hop := range path[1:] {
		s.hopStatSlice[idx] = *newHopStats(hop)
		s.hopToIdxMapping[hop.String()] = idx
	}

	return &s
}

func (s *probeStats) recordResponse(hop string, successful bool) {
	s.Lock()
	if successful {
		idx := s.hopToIdxMapping[hop]
		s.hopStatSlice[idx].success()
	} else {
		idx := s.hopToIdxMapping[hop]
		s.hopStatSlice[idx].failure()
	}
	s.Unlock()
}

func (s *probeStats) String() string {
	tableString := &strings.Builder{}
	tableString.WriteString(fmt.Sprintf("Probe %d packets through interface %s over path %v\n\n", s.totalPackets, s.interfaceDevice, s.path))

	table := tablewriter.NewWriter(tableString)

	rows := make([][]string, len(s.path)-1)
	for idx, hopStats := range s.hopStatSlice {
		rows[idx] = []string{
			fmt.Sprintf("%d", idx+1),
			hopStats.name,
			fmt.Sprintf("%.3f%%", hopStats.calculateSuccessRate()),
			fmt.Sprintf("%d", hopStats.packetsRecvd),
			fmt.Sprintf("%d", hopStats.packetsSent),
		}
	}

	table.SetHeader([]string{"idx", "hop", "success rate", "rx", "tx"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)
	table.AppendBulk(rows)
	table.Render()

	return tableString.String()
}

type hopStats struct {
	name         string
	packetsSent  int
	packetsRecvd int
}

func newHopStats(addr net.IP) *hopStats {
	return &hopStats{
		name:         addr.String(),
		packetsSent:  0,
		packetsRecvd: 0,
	}
}

func (hs *hopStats) calculateSuccessRate() float32 {
	if hs.packetsSent == 0 {
		return 0
	}

	return 100 * float32(hs.packetsRecvd) / float32(hs.packetsSent)
}

func (hs *hopStats) success() {
	hs.packetsSent++
	hs.packetsRecvd++
}

func (hs *hopStats) failure() {
	hs.packetsSent++
}
