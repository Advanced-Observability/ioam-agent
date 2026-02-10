package stats

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var (
	Ipv6PacketCount uint64 = 0
	IoamPacketCount uint64 = 0
)

func WriteStats(filename, iface string, interval time.Duration) {
	if interval == 0 {
		log.Println("[IOAM Agent CLT] Disabling statistics file")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Cannot open statistics file: %v", err)
		log.Println("[IOAM Agent CLT] Disabling statistics file")
		return
	}
	defer file.Close()

	rxf := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface)
	txf := fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface)
	init_rx, err := readInt(rxf)
	if err != nil {
		log.Printf("Cannot open file: %v", err)
		log.Println("[IOAM Agent CLT] Disabling statistics file")
		return
	}
	init_tx, err := readInt(txf)
	if err != nil {
		log.Printf("Cannot open file: %v", err)
		log.Println("[IOAM Agent CLT] Disabling statistics file")
		return
	}

	for range ticker.C {
		rx, rx_err := readInt(rxf)
		tx, tx_err := readInt(txf)
		if rx_err == nil && tx_err == nil {
			file.Seek(0, io.SeekStart)
			fmt.Fprintf(file, "%s parsed-ipv6=%d parsed-ioam=%d %s-rx=%d %s-tx=%d\n",
				time.Now().Format(time.RFC3339Nano), Ipv6PacketCount, IoamPacketCount, iface, rx-init_rx, iface, tx-init_tx)
		}
	}
}

func readInt(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		var count uint64
		fmt.Sscanf(scanner.Text(), "%d", &count)
		return count, nil
	}
	return 0, fmt.Errorf("failed to read file")
}
