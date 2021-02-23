package pfcpType

import (
	"encoding/binary"
	"fmt"

	"github.com/skoef/ndp"
)

type CasaICMPv6 struct {
	Pkt ndp.ICMP
}

func (i *CasaICMPv6) MarshalBinary() (data []byte, err error) {
	// Octet 5 to 8
	data = make([]byte, 2)
	binary.BigEndian.PutUint16(data, casa_vendor_id)
	icmpMsg, err := i.Pkt.Marshal()
	if err != nil {
		return
	}
	data = append(data, icmpMsg...)

	return data, nil
}

func (i *CasaICMPv6) UnmarshalBinary(data []byte) (err error) {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5 to 8
	if length < idx+2 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	vendor_id := binary.BigEndian.Uint16(data[idx:])
	if vendor_id != casa_vendor_id {
		return fmt.Errorf("Unknown vendor: %d", vendor_id)
	}
	idx = idx + 2
	i.Pkt, err = ndp.ParseMessage(data[idx:])
	if err != nil {
		return fmt.Errorf("Failed to decode ICMP Message: %v", err)
	}

	return nil
}
