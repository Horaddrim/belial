package lib

import (
	"log"
	"net"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
// note: loops until 'stop' receives data.
func ReadARP(waitGroup *sync.WaitGroup, handle *pcap.Handle, networkInterface *net.Interface, stop <-chan os.Signal) {
	defer waitGroup.Done()
	var packetCounter int
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Printf("Read %d ARP packets.\n", packetCounter)
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			packetCounter++

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				log.Printf("Who has %v? Tell %v", net.IP(arp.DstProtAddress), net.IP(arp.SourceProtAddress))
				continue
			}

			// Dump all information about ARP packages in the given interface,
			// since there maybe some packets flying that we do not ask for.
			log.Printf("IPv4 %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}
