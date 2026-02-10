//go:build !afpacket
// +build !afpacket

package main

import (
	"log"

	ioamAPI "github.com/Advanced-Observability/ioam-api"
	"github.com/google/gopacket"

	"github.com/Advanced-Observability/ioam-agent/internal/capture"
	"github.com/Advanced-Observability/ioam-agent/internal/config"
	"github.com/Advanced-Observability/ioam-agent/internal/parser"
	"github.com/Advanced-Observability/ioam-agent/internal/reporter"
	"github.com/Advanced-Observability/ioam-agent/internal/stats"
)

func main() {
	cfg := config.ParseFlags()
	source, err := capture.InitializeCapture(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}

	reportFunc := reporter.SetupReporting(cfg)
	go stats.WriteStats(cfg.Statfile, cfg.Interface, cfg.Interval)

	packets := make(chan gopacket.Packet, cfg.Workers)
	for w := uint(1); w <= cfg.Workers; w++ {
		go worker(w, packets, reportFunc)
	}

	for packet := range source.Packets() {
		packets <- packet
	}
}

func worker(id uint, packets <-chan gopacket.Packet, report func(*ioamAPI.IOAMTrace)) {
	for packet := range packets {
		parser.ParsePacket(packet, report)
	}
}

func sendBackPacket(ring *pfring.Ring, packet gopacket.Packet) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Println("Error: No Ethernet layer found in packet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		log.Println("Error: No IPv6 layer found in packet")
		return
	}
	ipv6, _ := ipv6Layer.(*layers.IPv6)

	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		log.Println("Error: No Hop-by-Hop Options header found in packet")
		return
	}
	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)

	// Swap source and destination MAC and IP addresses
	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
	ipv6.SrcIP, ipv6.DstIP = ipv6.DstIP, ipv6.SrcIP
	hbh.NextHeader = layers.IPProtocolNoNextHeader

	if err := gopacket.SerializeLayers(buffer, opts, eth, ipv6); err != nil {
		log.Printf("Error serializing layers: %v", err)
		return
	}

	if err := ring.WritePacketData(buffer.Bytes()); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func parseNodeData(data []byte, traceType uint32) (ioamAPI.IOAMNode, error) {
	node := ioamAPI.IOAMNode{}
	offset := 0

	if traceType&traceTypeBit0Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.Id = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&traceTypeBit1Mask != 0 {
		node.IngressId = uint32(binary.BigEndian.Uint16(data[offset:offset+2]))
		node.EgressId = uint32(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		offset += 4
	}
	if traceType&traceTypeBit2Mask != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit3Mask != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit4Mask != 0 {
		node.TransitDelay = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit5Mask != 0 {
		node.NamespaceData = data[offset : offset+4]
		offset += 4
	}
	if traceType&traceTypeBit6Mask != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit7Mask != 0 {
		node.CsumComp = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit8Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.IdWide = binary.BigEndian.Uint64(data[offset:offset+8]) & 0xFFFFFFFFFFFFFF
		offset += 8
	}
	if traceType&traceTypeBit9Mask != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(data[offset : offset+4])
		node.EgressIdWide = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}
	if traceType&traceTypeBit10Mask != 0 {
		node.NamespaceDataWide = data[offset : offset+8]
		offset += 8
	}
	if traceType&traceTypeBit11Mask != 0 {
		node.BufferOccupancy = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	return node, nil
}

func parseIOAMTrace(data []byte) (*ioamAPI.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("IOAM trace data too short")
	}

	ns := uint32(binary.BigEndian.Uint16(data[:2]))
	loopback := (data[2] & 0b00000010) != 0
	nodeLen := uint32(data[2] >> 3)
	remLen := uint32(data[3] & 0x7F)
	traceType := binary.BigEndian.Uint32(data[4:8]) >> 8
	traceId_High := binary.BigEndian.Uint64(data[8:16])
	traceId_Low := binary.BigEndian.Uint64(data[16:24])
	spanId := binary.BigEndian.Uint64(data[24:32])

	var nodes []*ioamAPI.IOAMNode
	offset := 32 + int(remLen)*4

	for offset < len(data) {
		node, err := parseNodeData(data[offset:offset+int(nodeLen)*4], traceType)
		if err != nil {
			return nil, false, err
		}
		offset += int(nodeLen) * 4

		if traceType&traceTypeBit22Mask != 0 {
			if len(data[offset:]) < 4 {
				return nil, false, errors.New("invalid packet length")
			}
			opaqueLen := data[offset]
			node.OSS.SchemaId = binary.BigEndian.Uint32(data[offset:offset+4])
			if len(data[offset:]) < 4+int(opaqueLen)*4 {
				return nil, false, errors.New("invalid packet length")
			}
			node.OSS.Data = data[offset+4:offset+4+int(opaqueLen)*4]
			offset += 4 + int(opaqueLen)*4
		}

		nodes = append([]*ioamAPI.IOAMNode{&node}, nodes...)
	}

	trace := &ioamAPI.IOAMTrace {
		TraceId_High: traceId_High,
		TraceId_Low:  traceId_Low,
		SpanId:		  spanId,
		BitField:     traceType << 8,
		NamespaceId:  ns,
		Nodes:        nodes,
	}

	return trace, loopback, nil
}

func parseHopByHop(data []byte) ([]*ioamAPI.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("Hop-by-Hop header too short")
	}

	hbhLen := int(data[1]+1) << 3
	offset := 2
	var traces []*ioamAPI.IOAMTrace
	var loopback bool

	for hbhLen > 0 {
		if len(data[offset:]) < 4 {
			return traces, false, nil
		}

		optType := data[offset]
		optLen := int(data[offset+1] + 2)

		if optType == ipv6TLVIOAM && data[offset+3] == ioamPreallocTrace {
			ioamPacketCount++

			trace, iloopback, err := parseIOAMTrace(data[offset+4 : offset+optLen])
			loopback = iloopback
			if err != nil {
				return nil, false, err
			}
			if trace != nil {
				traces = append(traces, trace)
			}
		}

		offset += optLen
		hbhLen -= optLen
	}

	return traces, loopback, nil
}

// grpcReport streams an IOAM trace to an IOAM collector
func grpcReport(trace *ioamAPI.IOAMTrace, stream ioamAPI.IOAMService_ReportClient) {
	if err := stream.Send(trace); err != nil {
		log.Printf("Error reporting trace: %v", err)
	}
}

func consoleReport(trace *ioamAPI.IOAMTrace) {
	fmt.Println(trace)
}

// Write various packet statistics to fileName every second
// Never returns, should be invoked as goroutine
func writeStats(fileName string, device string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Error opening stats file: %v", err)
	}
	defer file.Close()

	rxFilePath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", device)
	txFilePath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", device)

	rxFile, err := os.Open(rxFilePath)
	if err != nil {
		log.Fatalf("Error opening RX file: %v", err)
	}
	defer rxFile.Close()

	txFile, err := os.Open(txFilePath)
	if err != nil {
		log.Fatalf("Error opening TX file: %v", err)
	}
	defer txFile.Close()

	initialRX, err := readPacketCount(rxFile)
	if err != nil {
		log.Fatalf("Error reading initial RX packets: %v", err)
	}
	initialTX, err := readPacketCount(txFile)
	if err != nil {
		log.Fatalf("Error reading initial TX packets: %v", err)
	}

	for range ticker.C {
		currentRX, err := readPacketCount(rxFile)
		if err != nil {
			log.Fatalf("Error reading current RX packets: %v", err)
		}

		currentTX, err := readPacketCount(txFile)
		if err != nil {
			log.Fatalf("Error reading current TX packets: %v", err)
		}

		rxPacketCount := currentRX - initialRX
		txPacketCount := currentTX - initialTX

		// Update file statistics
		file.Seek(0, io.SeekStart)
		if _, err := fmt.Fprintf(file, "IPv6 packets parsed\t%d\nIOAM packets parsed\t%d\nPackets received\t%d\nPackets transmitted\t\t%d\n",
			ipv6PacketCount, ioamPacketCount, rxPacketCount, txPacketCount); err != nil {
			log.Fatalf("Error writing to stats file: %v", err)
		}
	}
}

func readPacketCount(file *os.File) (uint64, error) {
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}

	var count uint64
	_, err = fmt.Fscanf(file, "%d\n", &count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
