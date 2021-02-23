package ngapType

import "free5gc/lib/aper"

// Need to import "free5gc/lib/aper" if it uses "aper"

const (
	AuthenticatedIndicationPresentTrue aper.Enumerated = 0
)

type AuthenticatedIndication struct {
	Value aper.Enumerated `aper:"valueLB:0,valueUB:1"`
}
