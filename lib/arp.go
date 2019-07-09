package lib

type ARPPacket struct {
	SourceMACAddress      []byte
	SourceIPAddress       []byte
	DestinationMACAddress []byte
	DestinationIPAddress  []byte
}
