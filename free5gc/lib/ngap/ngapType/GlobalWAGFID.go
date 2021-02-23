package ngapType

//import "free5gc/lib/aper"

// Need to import "free5gc/lib/aper" if it uses "aper"

type GlobalWAGFID struct {
	PLMNIdentity PLMNIdentity
	WAGFID       WAGFID                                        `aper:"valueLB:0,valueUB:1"`
	IEExtensions *ProtocolExtensionContainerGlobalWAGFIDExtIEs `aper:"optional"`
}
