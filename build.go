package main

import (
	"fmt"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasConvert"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/ngap"
	"free5gc/lib/ngap/ngapConvert"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"sim-amf/pkg/context"
	"sim-amf/pkg/logger"
	amf_nas "sim-amf/pkg/nas"
	"sim-amf/pkg/types"
	"sim-amf/pkg/util"
)

// copied from src/test/ngapTestPacket/build.go, in case more changes for various test cases
func buildNGSetupResponse(amfName string, guamiList []ngapType.ServedGUAMIItem, plmnList []ngapType.PLMNSupportItem, amfRelativeCapacity int64) (pdu ngapType.NGAPPDU) {

	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successfulOutcome := pdu.SuccessfulOutcome
	successfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeNGSetup
	successfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
	successfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentNGSetupResponse
	successfulOutcome.Value.NGSetupResponse = new(ngapType.NGSetupResponse)

	nGSetupResponse := successfulOutcome.Value.NGSetupResponse
	nGSetupResponseIEs := &nGSetupResponse.ProtocolIEs

	// AMFName
	ie := ngapType.NGSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFName
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupResponseIEsPresentAMFName
	ie.Value.AMFName = new(ngapType.AMFName)

	aMFName := ie.Value.AMFName
	aMFName.Value = amfName

	nGSetupResponseIEs.List = append(nGSetupResponseIEs.List, ie)

	// ServedGUAMIList
	ie = ngapType.NGSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDServedGUAMIList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupResponseIEsPresentServedGUAMIList
	ie.Value.ServedGUAMIList = new(ngapType.ServedGUAMIList)

	servedGUAMIList := ie.Value.ServedGUAMIList
	servedGUAMIList.List = guamiList

	nGSetupResponseIEs.List = append(nGSetupResponseIEs.List, ie)

	// relativeAMFCapacity
	ie = ngapType.NGSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRelativeAMFCapacity
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.NGSetupResponseIEsPresentRelativeAMFCapacity
	ie.Value.RelativeAMFCapacity = new(ngapType.RelativeAMFCapacity)
	relativeAMFCapacity := ie.Value.RelativeAMFCapacity
	relativeAMFCapacity.Value = amfRelativeCapacity

	nGSetupResponseIEs.List = append(nGSetupResponseIEs.List, ie)

	// PLMNSupportList
	ie = ngapType.NGSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPLMNSupportList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupResponseIEsPresentPLMNSupportList
	ie.Value.PLMNSupportList = new(ngapType.PLMNSupportList)

	pLMNSupportList := ie.Value.PLMNSupportList
	pLMNSupportList.List = plmnList

	nGSetupResponseIEs.List = append(nGSetupResponseIEs.List, ie)

	return
}

func BuildSecurityModeCommand(ue *context.UEContext) ([]byte, error) {
	var nasMsg []byte
	var pdu []byte
	var err error
	nasMsg, err = buildSecurityModeCommnad(ue)
	if err != nil {
		logger.MainLog.Error("[TEST] Build Security Mode Command failed : %+v", err)
		return nasMsg, err
	}
	pdu, err = BuildDownlinkNasTransport(ue, nasMsg, nil)
	if err != nil {
		logger.MainLog.Error("[TEST] Build Down Link NAS Transport failed : %+v", err)
		return pdu, err
	}
	return pdu, err
}

func buildSecurityModeCommnad(ue *context.UEContext) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeCommand)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext,
	}

	securityModeCommand := nasMessage.NewSecurityModeCommand(0)
	securityModeCommand.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeCommand.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	securityModeCommand.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	securityModeCommand.SecurityModeCommandMessageIdentity.SetMessageType(nas.MsgTypeSecurityModeCommand)

	securityModeCommand.SelectedNASSecurityAlgorithms.SetTypeOfCipheringAlgorithm(ue.CipheringAlg)
	securityModeCommand.SelectedNASSecurityAlgorithms.SetTypeOfIntegrityProtectionAlgorithm(ue.IntegrityAlg)

	securityModeCommand.SpareHalfOctetAndNgksi = nasConvert.SpareHalfOctetAndNgksiToNas(ue.NgKsi)

	securityModeCommand.ReplayedUESecurityCapabilities.SetLen(ue.NasUESecurityCapability.GetLen())
	securityModeCommand.ReplayedUESecurityCapabilities.Buffer = ue.NasUESecurityCapability.Buffer

	securityModeCommand.IMEISVRequest = nasType.NewIMEISVRequest(nasMessage.SecurityModeCommandIMEISVRequestType)
	securityModeCommand.IMEISVRequest.SetIMEISVRequestValue(nasMessage.IMEISVNotRequested)

	securityModeCommand.Additional5GSecurityInformation = nasType.NewAdditional5GSecurityInformation(nasMessage.SecurityModeCommandAdditional5GSecurityInformationType)
	securityModeCommand.Additional5GSecurityInformation.SetLen(1)
	/*if ue.IsCleartext*/ {
		securityModeCommand.Additional5GSecurityInformation.SetRINMR(0)
	} /* else {
		securityModeCommand.Additional5GSecurityInformation.SetRINMR(1)
	}*/

	/*if ue.RegistrationType5GS == nasMessage.RegistrationType5GSPeriodicRegistrationUpdating || ue.RegistrationType5GS == nasMessage.RegistrationType5GSMobilityRegistrationUpdating {
		securityModeCommand.Additional5GSecurityInformation.SetHDP(1)
	} else*/{
		securityModeCommand.Additional5GSecurityInformation.SetHDP(0)
	}

	m.GmmMessage.SecurityModeCommand = securityModeCommand
	return m.PlainNasEncode()
}

func BuildDownlinkNasTransport(ue *context.UEContext, nasPdu []byte, mobilityRestrictionList *ngapType.MobilityRestrictionList) ([]byte, error) {

	var pdu ngapType.NGAPPDU

	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeDownlinkNASTransport
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentDownlinkNASTransport
	initiatingMessage.Value.DownlinkNASTransport = new(ngapType.DownlinkNASTransport)

	downlinkNasTransport := initiatingMessage.Value.DownlinkNASTransport
	downlinkNasTransportIEs := &downlinkNasTransport.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.DownlinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.DownlinkNASTransportIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = ue.AmfUeNgapId

	downlinkNasTransportIEs.List = append(downlinkNasTransportIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.DownlinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.DownlinkNASTransportIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ue.RanUeNgapId

	downlinkNasTransportIEs.List = append(downlinkNasTransportIEs.List, ie)

	// NAS PDU
	ie = ngapType.DownlinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.DownlinkNASTransportIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)

	ie.Value.NASPDU.Value = nasPdu

	downlinkNasTransportIEs.List = append(downlinkNasTransportIEs.List, ie)

	// Old AMF (optional)
	if ue.PreviousAMF != nil {
		ie = ngapType.DownlinkNASTransportIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDOldAMF
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.DownlinkNASTransportIEsPresentOldAMF
		ie.Value.OldAMF = new(ngapType.AMFName)
		ie.Value.OldAMF = ue.PreviousAMF.AMFName

		downlinkNasTransportIEs.List = append(downlinkNasTransportIEs.List, ie)
		ue.PreviousAMFIndex = ""
		ue.PreviousAMF = nil
	}

	return ngap.Encoder(pdu)
}

/*
M: Message Type, AMF UE NGAP ID, RAN UE NGAP ID, GUAMI, Allowed NSSAI, UE Security CApabilities, Security Key
*/
func BuildInitialContextSetupRequest(ue *context.UEContext, nasPdu []byte) ([]byte, error) {
	var pdu ngapType.NGAPPDU

	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeInitialContextSetup
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentInitialContextSetupRequest
	initiatingMessage.Value.InitialContextSetupRequest = new(ngapType.InitialContextSetupRequest)

	initialContextSetupRequest := initiatingMessage.Value.InitialContextSetupRequest
	initialContextSetupRequestIEs := &initialContextSetupRequest.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = ue.AmfUeNgapId

	initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ue.RanUeNgapId

	initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)

	// NAS PDU
	if nasPdu != nil {
		ie = ngapType.InitialContextSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDNASPDU
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentNASPDU
		ie.Value.NASPDU = new(ngapType.NASPDU)

		ie.Value.NASPDU.Value = nasPdu

		initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)
	}
	// Old AMF (optional)
	if ue.PreviousAMF != nil {
		ie = ngapType.InitialContextSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDOldAMF
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentOldAMF
		ie.Value.OldAMF = new(ngapType.AMFName)
		ie.Value.OldAMF = ue.PreviousAMF.AMFName

		initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)
		ue.PreviousAMFIndex = ""
		ue.PreviousAMF = nil
	}

	// GUAMI

	ie = ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDGUAMI
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentGUAMI
	ie.Value.GUAMI = new(ngapType.GUAMI)
	*ie.Value.GUAMI = ue.CurrentAMF.ServedGuamiList.List[0].GUAMI

	initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)

	// Allowed NSSAI
	ie = ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAllowedNSSAI
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentAllowedNSSAI
	ie.Value.AllowedNSSAI = ue.CurrentAMF.AllowedNssai

	initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)

	// UE Security Capabilities
	ie = ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUESecurityCapabilities
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentUESecurityCapabilities
	//ie.Value.UESecurityCapabilities = new(ngapType.UESecurityCapabilities)
	ie.Value.UESecurityCapabilities = ue.SecurityCapabilities

	// Security Key
	ie = ngapType.InitialContextSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSecurityKey
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentSecurityKey
	ie.Value.SecurityKey = new(ngapType.SecurityKey)

	securityKey := ie.Value.SecurityKey
	securityKey.Value = ngapConvert.ByteToBitString(ue.Kwagf, 256)

	initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)

	// UE Radio Capability (optional)
	if ue.RadioCapability != nil {
		ie = ngapType.InitialContextSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDUERadioCapability
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentUERadioCapability
		//ie.Value.UERadioCapability = new(ngapType.UERadioCapability)
		ie.Value.UERadioCapability = ue.RadioCapability

		initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)
	}
	/*
		// Resource Setup List (0..1)
		ie = ngapType.InitialContextSetupRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialContextSetupRequestIEsPresentSecurityKey
		ie.Value.PDUSessionResourceSetupListCxtReq = new(ngapType.PDUSessionResourceSetupListCxtReq)

		pDUSessionResourceSetupListCxtReq := ie.Value.PDUSessionResourceSetupListCxtReq
		pDUSessionResourceSetupItemCxtReq := ngapType.PDUSessionResourceSetupItemCxtReq {
		        PDUSessionID: ngapType.PDUSessionID{Value:1,},
			SNSSAI: ngapType.SNSSAI{
				SST: ngapType.SST{
					Value: []byte{1},
				},
				SD: &ngapType.SD{
					Value: []byte{0x11, 0x22, 0x33},
				}},
			PDUSessionResourceSetupRequestTransfer:,
		}
		pDUSessionResourceSetupListCxtReq.List = append(pDUSessionResourceSetupListCxtReq.List, )

		initialContextSetupRequestIEs.List = append(initialContextSetupRequestIEs.List, ie)
	*/
	return ngap.Encoder(pdu)
}

func BuildPDUSessionResourceSetupRequest(ue *context.UEContext, sessionId uint8) ([]byte, error) {
	var nasMsg []byte
	var pdu []byte
	var err error

	nasMsg, err = BuildPDUSessionEstablishmentAccept(ue, sessionId)
	if err != nil {
		return nasMsg, err
	}
	pdu, err = buildPDUSessionResourceSetupRequest(ue, sessionId, nasMsg)
	if err != nil {
		return pdu, err
	}
	return pdu, err
}

func BuildPDUSessionEstablishmentAccept(ue *context.UEContext, pdusessionID uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)

	pduSessionEstablishmentAccept := nasMessage.NewPDUSessionEstablishmentAccept(0xc2)
	pduSessionEstablishmentAccept.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	// PDUSessionID 9.4
	// PDUSessionID Row, sBit, len = [0, 0], 8 , 8
	pduSessionEstablishmentAccept.PDUSessionID.SetPDUSessionID(pdusessionID)
	// PTI 9.6
	// PTI Row, sBit, len = [0, 0], 8 , 8
	pduSessionEstablishmentAccept.PTI.SetPTI(0x01)
	pduSessionEstablishmentAccept.PDUSESSIONESTABLISHMENTACCEPTMessageIdentity.SetMessageType(nas.MsgTypePDUSessionEstablishmentAccept)
	pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType.SetSSCMode(3)        // SSC mode 3
	pduSessionEstablishmentAccept.SelectedSSCModeAndSelectedPDUSessionType.SetPDUSessionType(5) // Ethernet

	// TBD: some problem on AuthorizedQosRules
	pduSessionEstablishmentAccept.AuthorizedQosRules = nasType.AuthorizedQosRules{
		Len: 28,
		Buffer: []uint8{
			0x01, 0x00, 0x06, 0x31, 0x31, 0x01, 0x01, 0x00,
			0x3f, 0x02, 0x00, 0x10, 0x21, 0x35, 0x0b, 0x10,
			0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
			0x30, 0x24, 0x03, 0x12,
		},
	}
	pduSessionEstablishmentAccept.SessionAMBR = nasType.SessionAMBR{
		Len:   6,
		Octet: [6]uint8{0x06, 0x00, 0x04, 0x06, 0x00, 0x01},
	}

	m.GsmMessage.PDUSessionEstablishmentAccept = pduSessionEstablishmentAccept
	nasMsg, err := m.PlainNasEncode()
	if err != nil {
		return nasMsg, err
	}

	return BuildDLNASTransport(ue, nasMsg, &pdusessionID, nil, nil)
}

func BuildDLNASTransport(ue *context.UEContext, nasPdu []byte, pduSessionID *uint8, additionalInformation []uint8, cause5GMM *uint8) ([]byte, error) {

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDLNASTransport)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}

	dLNASTransport := nasMessage.NewDLNASTransport(0)
	dLNASTransport.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	dLNASTransport.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	dLNASTransport.DLNASTRANSPORTMessageIdentity.SetMessageType(nas.MsgTypeDLNASTransport)
	dLNASTransport.SpareHalfOctetAndPayloadContainerType.SetPayloadContainerType(nasMessage.PayloadContainerTypeN1SMInfo)
	if nasPdu == nil {
		return nil, fmt.Errorf("nasPdu is nil")
	}
	dLNASTransport.PayloadContainer.SetLen(uint16(len(nasPdu)))
	dLNASTransport.PayloadContainer.SetPayloadContainerContents(nasPdu)

	if pduSessionID != nil {
		dLNASTransport.PduSessionID2Value = new(nasType.PduSessionID2Value)
		dLNASTransport.PduSessionID2Value.SetIei(nasMessage.DLNASTransportPduSessionID2ValueType)
		dLNASTransport.PduSessionID2Value.SetPduSessionID2Value(*pduSessionID)
	}
	if additionalInformation != nil {
		info := nasType.NewAdditionalInformation(nasMessage.DLNASTransportAdditionalInformationType)
		info.SetLen(uint8(len(additionalInformation)))
		info.SetAdditionalInformationValue(additionalInformation)
		dLNASTransport.AdditionalInformation = info
	}
	if cause5GMM != nil {
		cause := nasType.NewCause5GMM(nasMessage.DLNASTransportCause5GMMType)
		cause.SetCauseValue(*cause5GMM)
		dLNASTransport.Cause5GMM = cause
	}
	// TODO: handle BackoffTimerValue

	m.GmmMessage.DLNASTransport = dLNASTransport

	return amf_nas.Encode(ue, m, false)
}

// nasPDU: from nas layer
// pduSessionResourceSetupRequestList: provided by AMF, and transfer data is from SMF
func buildPDUSessionResourceSetupRequest(ue *context.UEContext, pduSessionID uint8, nasPdu []byte) ([]byte, error) {
	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceSetup
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest
	initiatingMessage.Value.PDUSessionResourceSetupRequest = new(ngapType.PDUSessionResourceSetupRequest)

	PDUSessionResourceSetupRequest := initiatingMessage.Value.PDUSessionResourceSetupRequest
	PDUSessionResourceSetupRequestIEs := &PDUSessionResourceSetupRequest.ProtocolIEs

	ie := ngapType.PDUSessionResourceSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceSetupRequestIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)
	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = ue.AmfUeNgapId
	PDUSessionResourceSetupRequestIEs.List = append(PDUSessionResourceSetupRequestIEs.List, ie)

	ie = ngapType.PDUSessionResourceSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceSetupRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)
	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ue.RanUeNgapId
	PDUSessionResourceSetupRequestIEs.List = append(PDUSessionResourceSetupRequestIEs.List, ie)

	// NAS-PDU
	ie = ngapType.PDUSessionResourceSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceSetupRequestIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)
	nASPDU := ie.Value.NASPDU
	nASPDU.Value = nasPdu
	PDUSessionResourceSetupRequestIEs.List = append(PDUSessionResourceSetupRequestIEs.List, ie)

	ie = ngapType.PDUSessionResourceSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceSetupRequestIEsPresentPDUSessionResourceSetupListSUReq
	ie.Value.PDUSessionResourceSetupListSUReq = new(ngapType.PDUSessionResourceSetupListSUReq)
	setupReqItem := new(ngapType.PDUSessionResourceSetupItemSUReq)
	setupReqItem.PDUSessionID.Value = int64(pduSessionID)
	// hard code
	snssai := new(ngapType.SNSSAI)
	snssai.SST.Value = []uint8{0x01}
	setupReqItem.SNSSAI = *snssai
	setupReqItem.PDUSessionResourceSetupRequestTransfer = []uint8{
		0x00, 0x00, 0x04, 0x00, 0x82, 0x00, 0x06, 0x04, 0x03, 0xe8, 0x10, 0x03, 0xe8, 0x00, 0x8b, 0x00,
		0x0a, 0x01, 0xf0, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x16, 0x21, 0x2c, 0x00, 0x86, 0x00, 0x01, 0x00,
		0x00, 0x88, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x07, 0x24, 0x00,
	}
	ie.Value.PDUSessionResourceSetupListSUReq.List = append(ie.Value.PDUSessionResourceSetupListSUReq.List, *setupReqItem)
	PDUSessionResourceSetupRequestIEs.List = append(PDUSessionResourceSetupRequestIEs.List, ie)

	// UEAggregateMaximumBitRate
	ie = ngapType.PDUSessionResourceSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUEAggregateMaximumBitRate
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupRequestIEsPresentPDUUEAggregateMaximumBitRate
	ie.Value.UEAggregateMaximumBitRate = new(ngapType.UEAggregateMaximumBitRate)
	UEAggregateMaximumBitRate := ie.Value.UEAggregateMaximumBitRate
	UEAggregateMaximumBitRate.UEAggregateMaximumBitRateDL.Value = 200000000
	UEAggregateMaximumBitRate.UEAggregateMaximumBitRateUL.Value = 100000000
	PDUSessionResourceSetupRequestIEs.List = append(PDUSessionResourceSetupRequestIEs.List, ie)

	return ngap.Encoder(pdu)
}

func BuildPDUSessionResourceReleaseCommand(ue *context.UEContext, sessionId uint8) ([]byte, error) {
	var nasMsg []byte
	var pdu []byte
	var err error

	var cause5GMM uint8 = 0x24 // Regular deactivation
	nasMsg, err = BuildPDUSessionReleaseCommand(ue, sessionId, &cause5GMM)
	if err != nil {
		return nasMsg, err
	}
	pdu, err = buildPDUSessionResourceReleaseCommand(ue, nasMsg)
	if err != nil {
		return pdu, err
	}
	return pdu, err
}

func BuildPDUSessionReleaseCommand(ue *context.UEContext, pdusessionID uint8, cause5GMM *uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GsmMessage = nas.NewGsmMessage()
	m.GsmHeader.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)

	pduSessionReleaseCommand := nasMessage.NewPDUSessionReleaseCommand(0xd3)
	pduSessionReleaseCommand.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSSessionManagementMessage)
	// PDUSessionID 9.4
	// PDUSessionID Row, sBit, len = [0, 0], 8 , 8
	pduSessionReleaseCommand.PDUSessionID.SetPDUSessionID(pdusessionID)
	// PTI 9.6
	// PTI Row, sBit, len = [0, 0], 8 , 8
	pduSessionReleaseCommand.PTI.SetPTI(0x01)
	pduSessionReleaseCommand.PDUSESSIONRELEASECOMMANDMessageIdentity.SetMessageType(nas.MsgTypePDUSessionReleaseCommand)
	pduSessionReleaseCommand.Cause5GSM.SetCauseValue(*cause5GMM)

	// TODO: handle EAPMessage, ExtendedProtocolConfigurationOptions, BackoffTimerValue
	m.GsmMessage.PDUSessionReleaseCommand = pduSessionReleaseCommand
	nasMsg, err := m.PlainNasEncode()
	if err != nil {
		return nasMsg, err
	}

	return BuildDLNASTransport(ue, nasMsg, &pdusessionID, nil, nil)
}

func buildPDUSessionResourceReleaseCommand(ue *context.UEContext, nasPdu []byte) ([]byte, error) {

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodePDUSessionResourceRelease
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentPDUSessionResourceReleaseCommand
	initiatingMessage.Value.PDUSessionResourceReleaseCommand = new(ngapType.PDUSessionResourceReleaseCommand)

	pDUSessionResourceReleaseCommand := initiatingMessage.Value.PDUSessionResourceReleaseCommand
	PDUSessionResourceReleaseCommandIEs := &pDUSessionResourceReleaseCommand.ProtocolIEs

	// AMFUENGAPID
	ie := ngapType.PDUSessionResourceReleaseCommandIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceReleaseCommandIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = ue.AmfUeNgapId

	PDUSessionResourceReleaseCommandIEs.List = append(PDUSessionResourceReleaseCommandIEs.List, ie)

	// RANUENGAPID
	ie = ngapType.PDUSessionResourceReleaseCommandIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceReleaseCommandIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ue.RanUeNgapId

	PDUSessionResourceReleaseCommandIEs.List = append(PDUSessionResourceReleaseCommandIEs.List, ie)

	// NAS-PDU (optional)
	if nasPdu != nil {
		ie = ngapType.PDUSessionResourceReleaseCommandIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDNASPDU
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.PDUSessionResourceReleaseCommandIEsPresentNASPDU
		ie.Value.NASPDU = new(ngapType.NASPDU)

		ie.Value.NASPDU.Value = nasPdu

		PDUSessionResourceReleaseCommandIEs.List = append(PDUSessionResourceReleaseCommandIEs.List, ie)
	}

	// PDUSessionResourceToReleaseListRelCmd
	ie = ngapType.PDUSessionResourceReleaseCommandIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PDUSessionResourceReleaseCommandIEsPresentPDUSessionResourceToReleaseListRelCmd
	ie.Value.PDUSessionResourceToReleaseListRelCmd = new(ngapType.PDUSessionResourceToReleaseListRelCmd)
	// hard code
	item := ngapType.PDUSessionResourceToReleaseItemRelCmd{}
	item.PDUSessionID.Value = 1
	item.PDUSessionResourceReleaseCommandTransfer = []uint8{0x10}
	ie.Value.PDUSessionResourceToReleaseListRelCmd.List = append(ie.Value.PDUSessionResourceToReleaseListRelCmd.List, item)
	PDUSessionResourceReleaseCommandIEs.List = append(PDUSessionResourceReleaseCommandIEs.List, ie)

	return ngap.Encoder(pdu)
}

// amf/gmm/handle.go: HandleDeregistrationRequest
// lib/nas/nasTestPacket/NasPdu.go: GetDeregistrationRequest
func BuildDeregistrationRequest(ue *context.UEContext, switchOff uint8, reRegistrationRequired bool) ([]byte, error) {

	if ue == nil {
		return nil, fmt.Errorf("UE Context is nil when BuildDeregistrationRequest")
	}

	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    ue.SecurityHeaderType,
	}

	deregistrationRequest := nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(0)
	deregistrationRequest.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	deregistrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	deregistrationRequest.DeregistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)

	// accessType: 01 - 3gpp, 02 - non-3gpp, 03 - 3gpp & non-3gpp
	var accessType uint8
	switch ue.RGType {
	case types.RGType_FN_RG:
		accessType = 2
	case types.RGType_FIVEG_RG:
		accessType = 1
	default:
		accessType = 3
	}
	deregistrationRequest.NgksiAndDeregistrationType.SetAccessType(accessType)
	deregistrationRequest.NgksiAndDeregistrationType.SetSwitchOff(switchOff)
	if reRegistrationRequired {
		deregistrationRequest.NgksiAndDeregistrationType.SetReRegistrationRequired(nasMessage.ReRegistrationRequired)
	} else {
		deregistrationRequest.NgksiAndDeregistrationType.SetReRegistrationRequired(nasMessage.ReRegistrationNotRequired)
	}
	switch ue.NgKsi.Tsc {
	case models.ScType_NATIVE:
		deregistrationRequest.NgksiAndDeregistrationType.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	case models.ScType_MAPPED:
		deregistrationRequest.NgksiAndDeregistrationType.SetTSC(nasMessage.TypeOfSecurityContextFlagMapped)
	}
	deregistrationRequest.NgksiAndDeregistrationType.SetNasKeySetIdentifiler((uint8)(ue.NgKsi.Ksi))

	// TS 23.502 4.2.2.3.2 UE-Initiated Deregistration
	// The UE sends Deregistration Request (5G-GUTI, Deregistration Type, ngKSI) to the AMF.
	if len(ue.Guti) != 0 {
		mobileIdentity := util.GUTI5GToMobileIdentity5GS(nasConvert.GutiToNas(ue.Guti))
		deregistrationRequest.MobileIdentity5GS.SetIei(mobileIdentity.GetIei())
		deregistrationRequest.MobileIdentity5GS.SetLen(mobileIdentity.GetLen())
		deregistrationRequest.MobileIdentity5GS.SetMobileIdentity5GSContents(mobileIdentity.GetMobileIdentity5GSContents())
	} else {
		deregistrationRequest.MobileIdentity5GS.SetIei(ue.MobileIdentity.GetIei())
		deregistrationRequest.MobileIdentity5GS.SetLen(ue.MobileIdentity.GetLen())
		deregistrationRequest.MobileIdentity5GS.SetMobileIdentity5GSContents(ue.MobileIdentity.GetMobileIdentity5GSContents())
	}

	m.GmmMessage.DeregistrationRequestUEOriginatingDeregistration = deregistrationRequest
	return amf_nas.Encode(ue, m, false)
}

func BuildUplinkNASTransport(ue *context.UEContext, nasPdu []byte) ([]byte, error) {
	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeUplinkNASTransport
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUplinkNASTransport
	initiatingMessage.Value.UplinkNASTransport = new(ngapType.UplinkNASTransport)

	uplinkNasTransport := initiatingMessage.Value.UplinkNASTransport
	uplinkNasTransportIEs := &uplinkNasTransport.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = new(ngapType.AMFUENGAPID)

	aMFUENGAPID := ie.Value.AMFUENGAPID
	aMFUENGAPID.Value = ue.AmfUeNgapId

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ue.RanUeNgapId

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// NAS-PDU
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)
	nASPDU := ie.Value.NASPDU
	nASPDU.Value = nasPdu
	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	// User Location Information
	ie = ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = agfUserLocationInfo(ue)

	uplinkNasTransportIEs.List = append(uplinkNasTransportIEs.List, ie)

	return ngap.Encoder(pdu)
}

func agfUserLocationInfo(ue *context.UEContext) *ngapType.UserLocationInformation {
	var info *ngapType.UserLocationInformation
	// var lineType *ngapType.LineType
	if len(ue.GlobalID) == 0 {
		logger.MainLog.Error("missing ue GlobalID")
		return nil
	}
	/*switch ue.LineType {
	case "DSL", "dsl":
		lineType = &ngapType.LineType{
			Value: ngapType.LineTypePresentDS1,
		}
	case "PON", "pon":
		lineType = &ngapType.LineType{
			Value: ngapType.LineTypePresentPON,
		}
	default:
		logger.NgapLog.Error("invalie lineType: %s", ue.LineType)
		return nil
	}*/
	info = &ngapType.UserLocationInformation{
		Present: ngapType.UserLocationInformationPresentChoiceExtensions,
		ChoiceExtensions: &ngapType.ProtocolIESingleContainerUserLocationInformationExtIEs{
			Value: ngapType.UserLocationInformationExtIEs{
				Id: ngapType.ProtocolIEID{
					Value: ngapType.ProtocolIEIDUserLocationInformationWAGF,
				},
				Criticality: ngapType.Criticality{
					Value: ngapType.CriticalityPresentIgnore,
				},
				Value: ngapType.UserLocationInformationExtIEsValue{
					Present: ngapType.UserLocationInformationExtIEsPresentWAGF,
					UserLocationInformationWAGF: &ngapType.UserLocationInformationWAGF{
						Present: ngapType.UserLocationInformationWAGFPresentGlobalLineID,
						GlobalLineID: &ngapType.GlobalLineID{
							GlobalLineIdentity: ue.GlobalID,
							// TOFIX: need to fix it back when amf issue have fixed
							// LineType:           lineType,
						},
					},
				},
			},
		},
	}
	return info
}

func BuildRegistrationAccept(ue *context.UEContext) ([]byte, error) {
	var nasMsg []byte
	var pdu []byte
	var err error
	nasMsg, err = BuildRegistrationAccept(ue)
	if err != nil {
		return nasMsg, err
	}
	pdu, err = BuildDownlinkNasTransport(ue, nasMsg, nil)
	if err != nil {
		return pdu, err
	}
	return pdu, err
}
