package pfcpType

import (
	"encoding/binary"
	"fmt"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

type CasaDHCPv6 struct {
	Pkt dhcpv6.DHCPv6
}

func (v *CasaDHCPv6) MarshalBinary() (data []byte, err error) {
	// Octet 5 to 8
	data = make([]byte, 2)
	binary.BigEndian.PutUint16(data, casa_vendor_id)
	dhcpMsg := v.Pkt.ToBytes()
	data = append(data, dhcpMsg...)

	return data, nil
}

func (v *CasaDHCPv6) UnmarshalBinary(data []byte) (err error) {
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
	v.Pkt, err = dhcpv6.FromBytes(data[idx:])
	if err != nil {
		return fmt.Errorf("Failed to decode DHCPv6 Message: %v", err)
	}

	return nil
}
