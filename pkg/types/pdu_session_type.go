package types

// TS 24.501 Table 9.11.4.11.1: PDU session type information element
const (
	PDUSessionTypePresentIPv4         uint8 = 0x01
	PDUSessionTypePresentIPv6         uint8 = 0x02
	PDUSessionTypePresentIPv4v6       uint8 = 0x03
	PDUSessionTypePresentUnstructured uint8 = 0x04
	PDUSessionTypePresentEthernet     uint8 = 0x05
	PDUSessionTypePresentReserved     uint8 = 0x07
)

// TS 24.501 Table 9.11.4.11.1: PDU session type information element
const (
	PDUSessionTypeIPv4         string = "IPv4"
	PDUSessionTypeIPv6         string = "IPv6"
	PDUSessionTypeIPv4v6       string = "IPv4v6"
	PDUSessionTypeUnstructured string = "Unstructured"
	PDUSessionTypeEthernet     string = "Ethernet"
	PDUSessionTypeReserved     string = "Reserved"
)

// PDUSessionTypeConvertStringToUint8 convert the string to the corresponding uint8
func PDUSessionTypeConvertStringToUint8(str string) (integer uint8) {
	switch str {
	case PDUSessionTypeIPv4:
		integer = PDUSessionTypePresentIPv4
	case PDUSessionTypeIPv6:
		integer = PDUSessionTypePresentIPv6
	case PDUSessionTypeIPv4v6:
		integer = PDUSessionTypePresentIPv4v6
	case PDUSessionTypeUnstructured:
		integer = PDUSessionTypePresentUnstructured
	case PDUSessionTypeEthernet:
		integer = PDUSessionTypePresentEthernet
	case PDUSessionTypeReserved:
		integer = PDUSessionTypePresentReserved
	}

	return
}

// PDUSessionTypeConvertUint8ToString convert the uint8 to the corresponding string
func PDUSessionTypeConvertUint8ToString(integer uint8) (str string) {
	switch integer {
	case PDUSessionTypePresentIPv4:
		str = PDUSessionTypeIPv4
	case PDUSessionTypePresentIPv6:
		str = PDUSessionTypeIPv6
	case PDUSessionTypePresentIPv4v6:
		str = PDUSessionTypeIPv4v6
	case PDUSessionTypePresentUnstructured:
		str = PDUSessionTypeUnstructured
	case PDUSessionTypePresentEthernet:
		str = PDUSessionTypeEthernet
	}

	return
}
