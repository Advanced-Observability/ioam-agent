package reporter

import (
	"context"
	"fmt"
	"sync"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/Advanced-Observability/ioam-agent/internal/config"
	ioamAPI "github.com/Advanced-Observability/ioam-api/clt"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type Reporter func(trace *ioamAPI.IOAMTrace)

var (
	clientStream grpc.ClientStreamingClient[ioamAPI.IOAMTrace, emptypb.Empty]
	mu sync.Mutex
	lastRun   time.Time
	interval  = 5 * time.Second // Interval between attempts to reconnect to the collector
)

func SetupReporting(cfg *config.Config) Reporter {
	var reporters []Reporter

	if cfg.Console {
		log.Println("[IOAM Agent] Printing IOAM traces...")
		reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
			fmt.Println(trace)
		})
	}

	if cfg.Dumpfile != "" {
		log.Println("[IOAM Agent] Dumping IOAM traces to file...")
		f, err := os.OpenFile(cfg.Dumpfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Error opening file: %v", err)
		} else {
			fmt.Fprintf(f, "timestamp,namespace_id,tracetype,hop_limit,node_id,ingress_id,egress_id,timestamp_secs,timestamp_frac,transit_delay,queue_depth,csum_comp,buffer_occupancy,ingress_id_wide,egress_id_wide,id_wide,namespace_data,namespace_data_wide,oss_schema_id,oss_data\n")
			reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
				dumpToFile(trace, f)
			})
		}
	}

	collector := os.Getenv("IOAM_COLLECTOR")
	if collector == "" {
		collector = cfg.Collector
	}
	if collector != "" {
		reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
			sendToCollector(trace, collector)
		})
	}

	if len(reporters) == 0 {
		log.Fatal("[IOAM Agent] No IOAM reporting method configured")
	}

	return func(trace *ioamAPI.IOAMTrace) {
		for _, r := range reporters {
			// Could modify implementation to have one worker pool per reporter
			r(trace)
		}
	}
}

func sendToCollector(trace *ioamAPI.IOAMTrace, collector string) error {
	if clientStream != nil {
		if err := clientStream.Send(trace); err == nil {
			return nil
		} else {
			log.Printf("Failed to send IOAM trace to collector: %v", err)
		}
	}
	err := reconnectStream(collector)
	return err
}

func reconnectStream(collector string) error {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	wait := lastRun.Add(interval).Sub(now)
	if wait > 0 {
		return nil
	}
	lastRun = time.Now()

	log.Printf("Trying to connect to collector")
	conn, err := grpc.Dial(collector, grpc.WithInsecure())
	if err != nil {
		return err
	}

	client := ioamAPI.NewIOAMServiceClient(conn)
	clientStream, err = client.Report(context.Background())
	if err != nil {
		return err
	}
	log.Printf("Successfully setup gRPC stream to collector")

	return nil
}

func dumpToFile(trace *ioamAPI.IOAMTrace, f *os.File) {
	for _, node := range trace.GetNodes() {
		toPrint := fmt.Sprintf("%s,%d,%06x,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%04x,%08x,",
			time.Now().Format(time.RFC3339Nano), trace.GetNamespaceId(), trace.GetBitField(),
			node.GetHopLimit(), node.GetId(), node.GetIngressId(), node.GetEgressId(),
			node.GetTimestampSecs(), node.GetTimestampFrac(), node.GetTransitDelay(), node.GetQueueDepth(),
			node.GetCsumComp(), node.GetBufferOccupancy(), node.GetIngressIdWide(), node.GetEgressIdWide(),
			node.GetIdWide(), node.GetNamespaceData(), node.GetNamespaceDataWide())

		oss := node.GetOSS()
		if oss != nil {
			toPrint += fmt.Sprintf("%d,%x", oss.SchemaId, oss.Data)
		}
		toPrint += "\n"

		if _, err := f.WriteString(toPrint); err != nil {
			log.Printf("Error writing to file: %v", err)
		}
	}
}
