package types

import (
	"encoding/binary"
	"free5gc/lib/nas/nasType"

)

const (
	OperationCodeCreateNewQoSRule = uint8(iota + 1)
	OperationCodeDeleteExistingQoSRule
	OperationCodeModifyExistingQoSRuleAndAddPacketFilters
	OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters
	OperationCodeModifyExistingQoSRuleAndDeletePacketFilters
	OperationCodeModifyExistingQoSRuleWithoutModifyingPacketFilters
)

const (
	PacketFilterComponentTypeMatchAll                       uint8 = 0x01
	PacketFilterComponentTypeIPv4RemoteAddress              uint8 = 0x10
	PacketFilterComponentTypeIPv4LocalAddress               uint8 = 0x11
	PacketFilterComponentTypeIPv6RemoteAddress              uint8 = 0x21
	PacketFilterComponentTypeIPv6LocalAddress               uint8 = 0x23
	PacketFilterComponentTypeProtocolIdentifierOrNextHeader uint8 = 0x30
	PacketFilterComponentTypeSingleLocalPort                uint8 = 0x40
	PacketFilterComponentTypeLocalPortRange                 uint8 = 0x41
	PacketFilterComponentTypeSingleRemotePort               uint8 = 0x50
	PacketFilterComponentTypeRemotePortRange                uint8 = 0x51
	PacketFilterComponentTypeSecurityParameterIndex         uint8 = 0x60
	PacketFilterComponentTypeTypeOfServiceOrTrafficClass    uint8 = 0x70
	PacketFilterComponentTypeFlowLabel                      uint8 = 0x80
	PacketFilterComponentTypeDestinationMACAddress          uint8 = 0x81
	PacketFilterComponentTypeSourceMACAddress               uint8 = 0x82
	PacketFilterComponentType8021QCTAGVID                   uint8 = 0x83
	PacketFilterComponentType8021QSTAGVID                   uint8 = 0x84
	PacketFilterComponentType8021QCTAGPCPOrDEI              uint8 = 0x85
	PacketFilterComponentType8021QSTAGPCPOrDEI              uint8 = 0x86
	PacketFilterComponentTypeEthertype                      uint8 = 0x87
)

type AuthorizedQosRules []*QoSRule

type QoSRule struct {
	Identifier       uint8
	OperationCode    uint8
	DQR              uint8
	PacketFilterList []*PacketFilter
	Precedence       *uint8
	Segregation      *uint8
	QFI              *uint8
}

type PacketFilter struct {
	Direction  *uint8
	Identifier uint8
	Components []*PacketFilterComponent
}

// gitlab.casa-systems.com/mobility/common/nas/5gnas_evnt_common.h
type PacketFilterComponent struct {
	Type uint8
	*IPv4RemoteAddress
	*IPv4LocalAddress
	*IPv6RemoteAddress
	*IPv6LocalAddress
	*ProtocolIdentifierOrNextHeader
	*SingleLocalPort
	*LocalPortRange
	*SingleRemotePort
	*RemotePortRange
	*SecurityParameterIndex
	*TypeOfServiceOrTrafficClass
	*FlowLabel
	*DestinationMACAddress
	*SourceMACAddress
	*QCTAGVID
	*QSTAGVID
	*QCTAGPCPOrDEI
	*QSTAGPCPOrDEI
	*Ethertype
}

type IPv4Address struct {
	Addr [4]uint8
	Mask [4]uint8
}

type IPv4RemoteAddress struct {
	IPv4Address
}

type IPv4LocalAddress struct {
	IPv4Address
}

type IPv6Address struct {
	Addr      [16]uint8
	PerfixLen uint8
}

type IPv6RemoteAddress struct {
	IPv6Address
}

type IPv6LocalAddress struct {
	IPv6Address
}

type ProtocolIdentifierOrNextHeader struct {
	Spec uint8
}

type SinglePort struct {
	Port uint16
}

type SingleLocalPort struct {
	SinglePort
}

type PortRange struct {
	LowLimit  uint16
	HighLimit uint16
}

type LocalPortRange struct {
	PortRange
}

type SingleRemotePort struct {
	SinglePort
}

type RemotePortRange struct {
	PortRange
}

type SecurityParameterIndex struct {
	Index [4]uint8
}

type TypeOfServiceOrTrafficClass struct {
	Class uint8
	Mark  uint8
}

type FlowLabel struct {
	Label [3]uint8
}

type MACAddress struct {
	Addr [6]uint8
}

type DestinationMACAddress struct {
	MACAddress
}

type SourceMACAddress struct {
	MACAddress
}

type TAGVID struct {
	VID [2]uint8
}

type QCTAGVID struct {
	TAGVID
}

type QSTAGVID struct {
	TAGVID
}

type TAGPCPOrDEI struct {
	PCP uint8
	DEI uint8
}

type QCTAGPCPOrDEI struct {
	TAGPCPOrDEI
}

type QSTAGPCPOrDEI struct {
	TAGPCPOrDEI
}

type Ethertype struct {
	Ethertype uint16
}

func DecodePacketFilterComponents(packetFilter *PacketFilter, components []byte) {
	for len(components) != 0 {
		packetFilterComponent := new(PacketFilterComponent)
		packetFilterComponent.Type = components[0]

		switch packetFilterComponent.Type {
		case PacketFilterComponentTypeMatchAll:
			// For "match-all type", the packet filter component shall not include the
			// packet filter component value field.
			components = components[1:]
		case PacketFilterComponentTypeIPv4RemoteAddress:
			component := new(IPv4RemoteAddress)
			copy(component.Addr[:], components[1:5])
			copy(component.Mask[:], components[5:9])
			packetFilterComponent.IPv4RemoteAddress = component

			components = components[9:]
		case PacketFilterComponentTypeIPv4LocalAddress:
			component := new(IPv4LocalAddress)
			copy(component.Addr[:], components[1:5])
			copy(component.Mask[:], components[5:9])
			packetFilterComponent.IPv4LocalAddress = component

			components = components[9:]
		case PacketFilterComponentTypeIPv6RemoteAddress:
			component := new(IPv6RemoteAddress)
			copy(component.Addr[:], components[1:17])
			component.PerfixLen = components[17]
			packetFilterComponent.IPv6RemoteAddress = component

			components = components[18:]
		case PacketFilterComponentTypeIPv6LocalAddress:
			component := new(IPv6LocalAddress)
			copy(component.Addr[:], components[1:17])
			component.PerfixLen = components[17]
			packetFilterComponent.IPv6LocalAddress = component

			components = components[18:]
		case PacketFilterComponentTypeProtocolIdentifierOrNextHeader:
			component := new(ProtocolIdentifierOrNextHeader)
			component.Spec = components[1]
			packetFilterComponent.ProtocolIdentifierOrNextHeader = component

			components = components[2:]
		case PacketFilterComponentTypeSingleLocalPort:
			component := new(SingleLocalPort)
			component.Port = binary.BigEndian.Uint16(components[1:3])
			packetFilterComponent.SingleLocalPort = component

			components = components[3:]
		case PacketFilterComponentTypeLocalPortRange:
			component := new(LocalPortRange)
			component.LowLimit = binary.BigEndian.Uint16(components[1:3])
			component.HighLimit = binary.BigEndian.Uint16(components[3:5])
			packetFilterComponent.LocalPortRange = component

			components = components[5:]
		case PacketFilterComponentTypeSingleRemotePort:
			component := new(SingleRemotePort)
			component.Port = binary.BigEndian.Uint16(components[1:3])
			packetFilterComponent.SingleRemotePort = component

			components = components[3:]
		case PacketFilterComponentTypeRemotePortRange:
			component := new(RemotePortRange)
			component.LowLimit = binary.BigEndian.Uint16(components[1:3])
			component.HighLimit = binary.BigEndian.Uint16(components[3:5])
			packetFilterComponent.RemotePortRange = component

			components = components[5:]
		case PacketFilterComponentTypeSecurityParameterIndex:
			component := new(SecurityParameterIndex)
			copy(component.Index[:], components[1:5])
			packetFilterComponent.SecurityParameterIndex = component

			components = components[5:]
		case PacketFilterComponentTypeTypeOfServiceOrTrafficClass:
			component := new(TypeOfServiceOrTrafficClass)
			component.Class = components[1]
			component.Mark = components[2]
			packetFilterComponent.TypeOfServiceOrTrafficClass = component

			components = components[3:]
		case PacketFilterComponentTypeFlowLabel:
			component := new(FlowLabel)
			copy(component.Label[:], components[1:4])
			packetFilterComponent.FlowLabel = component

			components = components[4:]
		case PacketFilterComponentTypeDestinationMACAddress:
			component := new(DestinationMACAddress)
			copy(component.Addr[:], components[1:7])
			packetFilterComponent.DestinationMACAddress = component

			components = components[7:]
		case PacketFilterComponentTypeSourceMACAddress:
			component := new(SourceMACAddress)
			copy(component.Addr[:], components[1:7])
			packetFilterComponent.SourceMACAddress = component

			components = components[7:]
		case PacketFilterComponentType8021QCTAGVID:
			component := new(QCTAGVID)
			copy(component.VID[:], components[1:3])
			packetFilterComponent.QCTAGVID = component

			components = components[3:]
		case PacketFilterComponentType8021QSTAGVID:
			component := new(QSTAGVID)
			copy(component.VID[:], components[1:3])
			packetFilterComponent.QSTAGVID = component

			components = components[3:]
		case PacketFilterComponentType8021QCTAGPCPOrDEI:
			component := new(QCTAGPCPOrDEI)
			component.PCP = components[1]
			component.DEI = components[2]
			packetFilterComponent.QCTAGPCPOrDEI = component

			components = components[3:]
		case PacketFilterComponentType8021QSTAGPCPOrDEI:
			component := new(QSTAGPCPOrDEI)
			component.PCP = components[1]
			component.DEI = components[2]
			packetFilterComponent.QSTAGPCPOrDEI = component

			components = components[3:]
		case PacketFilterComponentTypeEthertype:
			component := new(Ethertype)
			component.Ethertype = binary.BigEndian.Uint16(components[1:3])
			packetFilterComponent.Ethertype = component

			components = components[3:]
		default:
			packetFilter = nil
		}
		packetFilter.Components = append(packetFilter.Components, packetFilterComponent)
	}
}

func DecodeAuthorizedQosRules(payload *nasType.AuthorizedQosRules) (authorizedQosRules AuthorizedQosRules) {
	var decodedAuthorizedQosRulesLength uint16
	buffer := payload.GetQosRule()

	for decodedAuthorizedQosRulesLength < payload.GetLen() {
		qosRule := new(QoSRule)

		qosRule.Identifier = buffer[0]
		currentAuthorizedQosRulesLength := 3 + binary.BigEndian.Uint16(buffer[1:3])
		qosRule.OperationCode = buffer[3] >> 5
		qosRule.DQR = (buffer[3] & 16) >> 4
		totalPacketFilterListNumber := buffer[3] & 15

		var decodedPacketFilterListNumber uint8
		var decodedPacketFilterListLength uint16
		buffer = buffer[4:]
		if qosRule.OperationCode == OperationCodeModifyExistingQoSRuleAndDeletePacketFilters {
			decodedPacketFilterListLength = uint16(totalPacketFilterListNumber)

			for decodedPacketFilterListNumber < totalPacketFilterListNumber {
				packetFilter := new(PacketFilter)
				packetFilter.Identifier = buffer[0] & 15
				qosRule.PacketFilterList = append(qosRule.PacketFilterList, packetFilter)

				decodedPacketFilterListNumber++
				buffer = buffer[1:]
			}
		} else if qosRule.OperationCode == OperationCodeCreateNewQoSRule || qosRule.OperationCode == OperationCodeModifyExistingQoSRuleAndAddPacketFilters || qosRule.OperationCode == OperationCodeModifyExistingQoSRuleAndReplaceAllPacketFilters {
			for decodedPacketFilterListNumber < totalPacketFilterListNumber {
				packetFilter := new(PacketFilter)

				direction := (buffer[0] & 48) >> 4
				packetFilter.Direction = &direction
				packetFilter.Identifier = buffer[0] & 15
				packetFilterComponentsLength := buffer[1]
				packetFilterComponents := buffer[2 : 2+packetFilterComponentsLength]

				if DecodePacketFilterComponents(packetFilter, packetFilterComponents); packetFilter == nil {
					return nil
				}
				qosRule.PacketFilterList = append(qosRule.PacketFilterList, packetFilter)

				decodedPacketFilterListNumber++
				decodedPacketFilterListLength += uint16(2 + packetFilterComponentsLength)
				buffer = buffer[2+packetFilterComponentsLength:]
			}
		}

		if decodedPacketFilterListLength+4 < currentAuthorizedQosRulesLength {
			tempPrecedence := buffer[0]
			if tempPrecedence == 80 {
				return nil
			}
			qosRule.Precedence = &tempPrecedence

			tempSegregation := (buffer[1] & 64) >> 6
			qosRule.Segregation = &tempSegregation
			tempQFI := buffer[1] & 63
			qosRule.QFI = &tempQFI

			buffer = buffer[2:]
		}

		authorizedQosRules = append(authorizedQosRules, qosRule)
		decodedAuthorizedQosRulesLength += currentAuthorizedQosRulesLength
	}

	return
}
