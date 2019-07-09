package lib

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// BuildCustomARPPacket writes up a custom package forged for a specific network interface and
// can be customized by changing the Source MAC address, the Destination MAC address
// the Source IP address and the Destination IP address
func BuildCustomARPPacket(arpData ARPPacket) (result gopacket.SerializeBuffer) {
	ethHeader := layers.Ethernet{
		SrcMAC:       arpData.SourceMACAddress,
		DstMAC:       arpData.DestinationMACAddress,
		EthernetType: layers.EthernetTypeARP,
	}

	arpHeader := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   arpData.SourceMACAddress,
		SourceProtAddress: arpData.SourceIPAddress,
		DstHwAddress:      arpData.DestinationMACAddress,
		DstProtAddress:    arpData.DestinationIPAddress,
	}

	// Set up buffer and options for serialization.
	result = gopacket.NewSerializeBuffer()
	serializationOptions := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(result, serializationOptions, &ethHeader, &arpHeader)
	return
}

// WriteARP writes an ARP request for the broadcast address to the
// pcap handle.
func WriteARP(handle *pcap.Handle, networkInterface *net.Interface, addr *net.IPNet) error {
	packet := ARPPacket{
		SourceMACAddress: networkInterface.HardwareAddr,
		SourceIPAddress:  []byte(addr.IP),
		// This sets the packet to go to the broadcast address
		DestinationMACAddress: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	// Send one packet for every address.
	for _, ip := range CalculateIPs(addr) {
		packet.DestinationIPAddress = []byte(ip)

		bARP := BuildCustomARPPacket(packet)

		if err := handle.WritePacketData(bARP.Bytes()); err != nil {
			log.Printf("[ERROR] Cannot write packets on %v: %v", networkInterface.Name, err)
			return err
		}
	}

	return nil
}

func startInterval(interval string, channel chan<- int) chan int {
	duration, _ := time.ParseDuration(interval)

	for {
		channel <- 1
		time.Sleep(duration)
	}
}

func WriteARPOnInterval(interval string, stopChannel <-chan os.Signal, waitGroup *sync.WaitGroup, handle *pcap.Handle, networkInterface *net.Interface, validAddress *net.IPNet) {
	defer waitGroup.Done()
	timerChannel := make(chan int)

	go startInterval(interval, timerChannel)

	for {
		select {
		case <-stopChannel:
			return
		case <-timerChannel:
			// Write our scan packets out to the handle.
			if err := WriteARP(handle, networkInterface, validAddress); err != nil {
				log.Printf("[ERROR] Cannot write packets on %v: %v", networkInterface.Name, err)
				return
			}

			log.Println("Requested ARP replies for broadcast")
		}
	}
}
