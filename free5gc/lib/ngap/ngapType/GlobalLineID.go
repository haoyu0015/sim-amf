package ngapType

import "free5gc/lib/aper"

type GlobalLineID struct {
	GlobalLineIdentity aper.OctetString
	LineType           *LineType                                     `aper:"optional"`
	IEExtentions       *ProtocolExtensionContainerGlobalLineIDExtIEs `aper:"optional"`
}
