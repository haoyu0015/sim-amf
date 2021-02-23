package ngapType

//import "free5gc/lib/aper"

const (
	UserLocationInformationWAGFPresentNothing int = iota /* No components present */
	UserLocationInformationWAGFPresentGlobalLineID
	UserLocationInformationWAGFPresentHfcNodeID
	UserLocationInformationWAGFPresentChoiceExtensions
)

type UserLocationInformationWAGF struct {
	Present          int
	GlobalLineID 	 *GlobalLineID		`aper:"sizeLB:1,sizeUB:1"`
	HfcNodeID    	 *HfcNodeID 		`aper:"valueExt"`
	ChoiceExtensions *ProtocolIESingleContainerUserLocationInformationWAGFExtIEs
}
