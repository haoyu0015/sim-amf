package pfcpType

import "fmt"

type QFI struct {
	QFIdata uint8
}

func (qfi *QFI) MarshalBinary() (data []byte, err error) {
	// Octet 5
	data = append([]byte(""), byte(qfi.QFIdata))

	return data, nil
}

func (qfi *QFI) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5
	if length < idx+1 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	qfi.QFIdata = uint8(data[idx])
	idx = idx + 1

	if length != idx {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
