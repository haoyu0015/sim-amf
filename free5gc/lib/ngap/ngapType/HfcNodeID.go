package ngapType

import "free5gc/lib/aper"

// Need to import "free5gc/lib/aper" if it uses "aper"

type HfcNodeID struct {
	Value aper.OctetString `aper:"sizeLB:4,sizeUB:4"`
}
