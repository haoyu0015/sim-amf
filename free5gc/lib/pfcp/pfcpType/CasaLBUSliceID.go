package pfcpType

import (
	"encoding/binary"
	"fmt"
)

const casa_vendor_id uint16 = 20858

type CasaLBUSliceID struct {
	SliceId uint16
}

func (s *CasaLBUSliceID) MarshalBinary() (data []byte, err error) {
	// Octet 5 to 8
	data = make([]byte, 2)
	binary.BigEndian.PutUint16(data, casa_vendor_id)
	SliceId := make([]byte, 2)
	binary.BigEndian.PutUint16(SliceId, s.SliceId)
	data = append(data, SliceId...)

	return data, nil
}

func (s *CasaLBUSliceID) UnmarshalBinary(data []byte) error {
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
	s.SliceId = binary.BigEndian.Uint16(data[idx:])
	idx = idx + 2

	if length != idx {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
