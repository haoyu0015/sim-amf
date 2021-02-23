package ngapType

import "free5gc/lib/aper"

const (
	WAGFIDPresentNothing int = iota /* No components present */
	WAGFIDPresentWAGFID
	WAGFIDPresentChoiceExtensions
)

type WAGFID struct {
	Present          int
	WAGFID           *aper.BitString `aper:"sizeLB:16,sizeUB:16"`
	ChoiceExtensions *ProtocolIESingleContainerWAGFIDExtIEs
}
