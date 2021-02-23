package context

import (
	"bytes"
	"free5gc/lib/aper"
	"free5gc/lib/ngap/ngapConvert"
	"free5gc/lib/ngap/ngapType"
	"sync"

	//"git.cs.nctu.edu.tw/calee/sctp"

	"gitlab.casa-systems.com/opensource/sctp"
)

type AMFContext struct {
	AMFBasic

	SCTPConn             *sctp.SCTPConn
	UEContextAMFUENGAPID sync.Map // map[string]*context.UEContext, AMFUENGAPID as key
}

type AMFBasic struct {
	SCTPAddr            string
	AMFName             *ngapType.AMFName
	ServedGuamiList     *ngapType.ServedGUAMIList
	RelativeAMFCapacity *ngapType.RelativeAMFCapacity
	PlmnSupportList     *ngapType.PLMNSupportList
	AllowedNssai        *ngapType.AllowedNSSAI

	AMFTNLAssociationList map[string]*AMFTNLAssociationItem // v4+v6 as key
	// Overload related
	AMFOverloadContent *AMFOverloadContent
}

type AMFTNLAssociationItem struct {
	Ipv4                   string
	Ipv6                   string
	TNLAssociationUsage    *ngapType.TNLAssociationUsage
	TNLAddressWeightFactor *int64
}

type AMFOverloadContent struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}
type SliceOverloadItem struct {
	SNssaiList []ngapType.SNSSAI
	Action     *ngapType.OverloadAction
	TrafficInd *int64
}

func (amf *AMFContext) AddAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	item := &AMFTNLAssociationItem{}
	item.Ipv4, item.Ipv6 = ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	amf.AMFTNLAssociationList[item.Ipv4+item.Ipv6] = item
	return item
}

func (amf *AMFContext) FindAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) *AMFTNLAssociationItem {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	return amf.AMFTNLAssociationList[v4+v6]
}

func (amf *AMFContext) DeleteAMFTNLAssociationItem(info ngapType.CPTransportLayerInformation) {
	v4, v6 := ngapConvert.IPAddressToString(*info.EndpointIPAddress)
	delete(amf.AMFTNLAssociationList, v4+v6)
}

func (amf *AMFContext) StartOverload(resp *ngapType.OverloadResponse, trafloadInd *ngapType.TrafficLoadReductionIndication, nssai *ngapType.OverloadStartNSSAIList) *AMFOverloadContent {
	if resp == nil && trafloadInd == nil && nssai == nil {
		return nil
	}
	content := AMFOverloadContent{}
	if resp != nil {
		content.Action = resp.OverloadAction
	}
	if trafloadInd != nil {
		content.TrafficInd = &trafloadInd.Value
	}
	if nssai != nil {
		for _, item := range nssai.List {
			sliceItem := SliceOverloadItem{}
			for _, item2 := range item.SliceOverloadList.List {
				sliceItem.SNssaiList = append(sliceItem.SNssaiList, item2.SNSSAI)
			}
			if item.SliceOverloadResponse != nil {
				sliceItem.Action = item.SliceOverloadResponse.OverloadAction
			}
			if item.SliceTrafficLoadReductionIndication != nil {
				sliceItem.TrafficInd = &item.SliceTrafficLoadReductionIndication.Value
			}
			content.NSSAIList = append(content.NSSAIList, sliceItem)
		}
	}
	amf.AMFOverloadContent = &content
	return amf.AMFOverloadContent
}
func (amf *AMFContext) StopOverload() {
	amf.AMFOverloadContent = nil
}

// FindAvalibleAMFByCompareGUAMI compares the incoming GUAMI with AMF served GUAMI
// and return if this AMF is avalible for UE
func (amf *AMFContext) FindAvalibleAMFByCompareGUAMI(ueSpecifiedGUAMI *ngapType.GUAMI) bool {
	for _, amfServedGUAMI := range amf.ServedGuamiList.List {
		codedAMFServedGUAMI, err := aper.MarshalWithParams(&amfServedGUAMI.GUAMI, "valueExt")
		if err != nil {
			return false
		}
		codedUESpecifiedGUAMI, err := aper.MarshalWithParams(ueSpecifiedGUAMI, "valueExt")
		if err != nil {
			return false
		}
		if !bytes.Equal(codedAMFServedGUAMI, codedUESpecifiedGUAMI) {
			continue
		}
		return true
	}
	return false
}

// LoadUEContextAMFUENGAPID returns the UEContext stored in the UEContextAMFUENGAPID for a AMFUENGAPID, or nil if no
// UEContext is present. The bool result indicates whether UEContext was found in the UEContextAMFUENGAPID.
func (amf *AMFContext) LoadUEContextAMFUENGAPID(amfUENGAPID int64) (*UEContext, bool) {
	if value, ok := amf.UEContextAMFUENGAPID.Load(amfUENGAPID); ok {
		return value.(*UEContext), true
	}

	return nil, false
}

// StoreUEContextAMFUENGAPID sets the UEContext for a AMFUENGAPID
func (amf *AMFContext) StoreUEContextAMFUENGAPID(ueContext *UEContext) {
	if ueContext.AmfUeNgapId == AmfUeNgapIdUnspecified {
	} else {
		amf.UEContextAMFUENGAPID.Store(ueContext.AmfUeNgapId, ueContext)
	}
}

// DeleteUEContextAMFUENGAPID deletes the UEContext for a AMFUENGAPID
func (amf *AMFContext) DeleteUEContextAMFUENGAPID(amfUENGAPID int64) {
	amf.UEContextAMFUENGAPID.Delete(amfUENGAPID)
}

// EmptyUEContext deletes all the UEContexts in the UEContextAMFUENGAPID
func (amf *AMFContext) EmptyUEContext() {
	amf.UEContextAMFUENGAPID.Range(func(key, value interface{}) bool {
		amf.UEContextAMFUENGAPID.Delete(key)
		return true
	})
}
