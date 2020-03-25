package main

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/trstruth/beacon"

	"github.com/olekukonko/tablewriter"
)

type sprayStats struct {
	sync.RWMutex
	path            beacon.Path
	source          string
	dest            string
	hopToIdxMapping map[string]int
	hopStatSlice    []hopStats
}

func newSprayStats(path beacon.Path) *sprayStats {
	s := sprayStats{
		path:            path,
		source:          path[0].String(),
		dest:            path[len(path)-1].String(),
		hopToIdxMapping: make(map[string]int),
		hopStatSlice:    make([]hopStats, len(path)-1),
	}

	for idx, hop := range path[1:] {
		s.hopStatSlice[idx] = *newHopStats(hop)
		s.hopToIdxMapping[hop.String()] = idx
	}

	return &s
}

func (s *sprayStats) recordResponse(hop string, successful bool) {
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

func (s *sprayStats) String() string {
	// header := fmt.Sprintf("Spray from %s to %s", s.source, s.dest)
	// columnNames := fmt.Sprintf("idx   hop        success rate         rx     tx")
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)

	rows := make([][]string, len(s.path)-1)
	for idx, hopStats := range s.hopStatSlice {
		// rows[idx] = fmt.Sprintf("%d - %s    %3f%%        %d     %d", idx+1, hopStats.name, hopStats.calculateSuccessRate(), hopStats.packetsRecvd, hopStats.packetsSent)
		rows[idx] = []string{
			fmt.Sprintf("%d", idx+1),
			hopStats.name,
			fmt.Sprintf("%.3f%%", hopStats.calculateSuccessRate()),
			fmt.Sprintf("%d", hopStats.packetsRecvd),
			fmt.Sprintf("%d", hopStats.packetsSent),
		}
	}

	/*
		outputRows := append([]string{header, columnNames}, rows...)

		return strings.Join(outputRows, "\n")
	*/
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
