package ngapType

import "free5gc/lib/aper"

// Need to import "free5gc/lib/aper" if it uses "aper"

const (
	LineTypePresentDS1 aper.Enumerated = 0
	LineTypePresentPON aper.Enumerated = 1
)

type LineType struct {
	Value aper.Enumerated `aper:"valueLB:0,valueUB:1"`
}
