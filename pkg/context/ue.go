package context

import (
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"time"

	"free5gc/lib/aper"
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/nas/security"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"

	"sim-amf/pkg/types"
)

const (
	AmfUeNgapIdUnspecified   int64 = math.MaxUint32
	RanUeNgapIdUnspecified   int64 = math.MaxUint32
	MaxRegistrationRetryTime int   = 1
	// MaxRegistrationAttemptTime int = 1
	MaxRegistrationAttemptTime int = 5
	MaxServiceAttemptTime      int = 1
	MaxDeregistrationRetryTime int = 4
	MaxT3580RetryTimes         int = 5
	MaxT3582RetryTimes         int = 5
	// DefaultT3502Value int = 2
	DefaultT3502Value int = 12 * 60 // Default 12 minutes
	DefaultT3510Value int = 15
	// DefaultT3511Value                      int = 1
	// DefaultT3517Value                      int = 1
	// DefaultT3521Value                      int = 1
	// DefaultT3525Value                      int = 1
	// DefaultT3540Value                      int = 1
	DefaultT3511Value                      int = 10
	DefaultT3517Value                      int = 15
	DefaultT3521Value                      int = 15
	DefaultT3525Value                      int = 60
	DefaultT3540Value                      int = 10
	DefaultT3580Value                      int = 16
	DefaultT3582Value                      int = 16
	DefaultNon3GppDeregistrationTimerValue int = 54 * 60
)

type UEContext struct {
	UEBasic

	CurrentAMF  *AMFContext
	PreviousAMF *AMFContext

	Restoring                     bool
	SM                            map[types.RGType]*fsm.FSM
	BinarySemaphoreDeregistration chan struct{}
	Timers
}

type UEBasic struct {
	// Identify
	RanUeNgapId          int64
	AmfUeNgapId          int64
	LineID               []byte
	LineType             string
	MAC                  string
	RGType               types.RGType
	AutoCreatePDUSession bool
	MacUnique            bool
	GlobalIDStr          string
	GlobalID             aper.OctetString
	GlobalIDSUPI         string
	CircuitID            string
	RemoteID             string
	WAgfInfo             types.WAgfInfo
	GtpBindAddr          string

	MaskedIMEISV *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54

	Rid                   uint8 //RoutingIndicator
	Schid                 uint8 //ProtectionSchemeId
	Supi                  string
	Suci                  string
	Imsi                  string
	RRCEstablishmentCause int16

	// Index
	CurrentAMFIndex   string // SCTPRemoteAddr as key
	PreviousAMFIndex  string // SCTPRemoteAddr as key
	StateMachineIndex fsm.State

	// PDU Session
	Establishing                 bool
	EstablishingPduSessionType   string
	PduSessionIDList             map[int64]bool                     // pduSessionID as key
	PduSessionList               map[int64]*PDUSession              // pduSessionID as key
	PduSessionExtendedList       map[int64]*PDUSessionExtended      // pduSessionID as key
	AuthorizedQosRulesList       map[int64]types.AuthorizedQosRules // pduSessionID as key, authorizedQosRules as value
	TemporaryPDUSessionSetupData *PDUSessionSetupTemporaryData

	ULCount                  types.Count
	DLCount                  types.Count
	MacFailed                bool
	NgKsi                    models.NgKsi
	KnasInt                  [16]uint8 // 16 byte
	KnasEnc                  [16]uint8 // 16 byte
	Kwagf                    []uint8   // 32 bytes
	SecurityContextAvailable bool
	SecurityCapabilities     *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86
	NasUESecurityCapability  *nasType.UESecurityCapability    // for registration request
	CipheringAlg             uint8
	IntegrityAlg             uint8
	SecurityHeaderType       uint8

	// From RG
	RegistrationType uint8
	SupiType         uint8
	IdentityType     uint8
	Nai              string
	MobileIdentity   *nasType.MobileIdentity5GS
	ServiceType      uint8
	TimeZone         string
	Attached         uint8
	DetachCause      uint8

	// From Network
	RegistrationCause   uint8
	Guti                string
	Guami               models.Guami
	TMSI5G              [4]uint8
	IndexToRfsp         int64
	Ambr                *ngapType.UEAggregateMaximumBitRate
	RequestedNssai      []models.Snssai
	AllowedNssai        []models.Snssai
	RejectedNssaiInPlmn []models.Snssai
	RejectedNssaiInTai  []models.Snssai
	ConfiguredNssai     []models.Snssai
	TAIList             []models.Tai

	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                uint8

	T3502Value                      int
	T3510Value                      int
	T3511Value                      int
	T3517Value                      int
	T3521Value                      int
	T3525Value                      int
	T3540Value                      int
	Non3GppDeregistrationTimerValue int

	T3502RetryTimes                      int
	T3510RetryTimes                      int
	T3511RetryTimes                      int
	T3517RetryTimes                      int
	T3521RetryTimes                      int
	T3525RetryTimes                      int
	T3540RetryTimes                      int
	Non3GppDeregistrationTimerRetryTimes int

	MaxRegistrationRetryTime   int // T3502
	MaxRegistrationAttemptTime int // T3510
	MaxServiceAttemptTime      int // T3517
	MaxDeregistrationRetryTime int // T3521
	MaxServiceRetryTime        int // T3525
	LastRegistrationPkg        []byte

	T3580Value int
	// T3581Value int
	T3582Value int
	T3583Value int
	// T3584Value int
	// T3585Value int

	T3580RetryTimes int
	// T3581RetryTimes int
	T3582RetryTimes int
	T3583RetryTimes int
	// T3584RetryTimes int
	// T3585RetryTimes int

	MaxT3580RetryTimes int
	// MaxT3581RetryTimes int
	MaxT3582RetryTimes int
	MaxT3583RetryTimes int
	// MaxT3584RetryTimes int
	// MaxT3585RetryTimes int
}

type Timers struct {
	// 5GS Mobility Management Messages
	T3502                      *time.Timer
	T3510                      *time.Timer
	T3511                      *time.Timer
	T3517                      *time.Timer
	T3521                      *time.Timer
	T3525                      *time.Timer
	T3540                      *time.Timer
	Non3GppDeregistrationTimer *time.Timer

	// 5GS Session Management Messages
	T3580 *time.Timer
	//T3581 *time.Timer
	T3582 *time.Timer
	T3583 *time.Timer
	//T3584 *time.Timer
	//T3585 *time.Timer
}

// Constants definition of State and Cause
const (
	// 5GS Mobility Management Messages
	UEStateRegistrationRejected         string = "RegistrationRejected"         // Registration Reject
	UEStateServiceRejected              string = "ServiceRejected"              // Service Reject
	UEStateSecurityModeRejected         string = "SecurityModeRejected"         // Security Mode Reject
	UEStateDeregistered                 string = "Deregistered"                 // UE Context Release Command, NG Reset
	UEStateRegistrationRequestTimeout   string = "RegistrationRequestTimeout"   // T3510, T3502
	UEStateServiceRequestTimeout        string = "ServiceRequestTimeout"        // T3517, T3525
	UEStateDeregistrationRequestTimeout string = "DeregistrationRequestTimeout" // T3521
	UEStateUnimplemented                string = "Unimplemented"                // T3540
	// 5GS Session Management Messages
	PDUSessionStateEstablished           string = "Established"           // PDU Session Resource Setup Response
	PDUSessionStateEstablishingRejected  string = "EstablishingRejected"  // PDU Session Establishment Request
	PDUSessionStateEstablishmentRejected string = "EstablishmentRejected" // PDU Session Establishment Reject
	PDUSessionStateEstablishmentFailed   string = "EstablishmentFailed"   // message.BuildPDUSessionResourceSetupResponseTransfer
	PDUSessionStateReleased              string = "Released"              // PDU Session Resource Release Command
	PDUSessionStateReleaseRejected       string = "ReleaseRejected"       // PDU Session Release Reject

	PDUSessionCauseMissingQosInfoPerTNL     string = "Missing N3SetupResourceResult.QosInfoPerTNL"                   // message.BuildPDUSessionResourceSetupResponseTransfer
	PDUSessionCauseMissingAssociatedQosList string = "Missing N3SetupResourceResult.QosInfoPerTNL.AssociatedQosList" // message.BuildPDUSessionResourceSetupResponseTransfer
)

type PDUSessionExtended struct {
	Type  string
	State string
	Cause string
}

type PDUSession struct {
	Id                               int64 // PDU Session ID
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai                           ngapType.SNSSAI
	NetworkInstance                  *ngapType.NetworkInstance
	SecurityCipher                   bool
	SecurityIntegrity                bool
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QFIList                          []uint8
	QosFlows                         map[int64]*QosFlow // QosFlowIdentifier as key
}

type PDUSessionSetupTemporaryData struct {
	// Slice of unactivated PDU session
	UnactivatedPDUSession []int64 // PDUSessionID as content
	// NGAPProcedureCode is used to identify which type of
	// response shall be used
	NGAPProcedureCode ngapType.ProcedureCode
	// PDU session setup list response
	SetupListCxtRes  *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes   *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes  *ngapType.PDUSessionResourceFailedToSetupListSURes
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

type GTPConnectionInfo struct {
	UPFIPAddr    string
	UPFUDPAddr   net.Addr
	IncomingTEID uint32
	OutgoingTEID uint32
}

type UDPSocketInfo struct {
	Conn    *net.UDPConn
	AGFAddr *net.UDPAddr
	UEAddr  *net.UDPAddr
}

// GiveBinarySemaphoreDeregistration gives a binary semaphore for Deregistration
func (ue *UEContext) GiveBinarySemaphoreDeregistration() {
	ue.BinarySemaphoreDeregistration <- struct{}{}
}

// TakeBinarySemaphoreDeregistration is taking a binary semaphore for Deregistration
func (ue *UEContext) TakeBinarySemaphoreDeregistration() {
	<-ue.BinarySemaphoreDeregistration
}

func (ue *UEContext) Init(ranUeNgapId int64) {
	ue.RanUeNgapId = ranUeNgapId
	ue.AmfUeNgapId = AmfUeNgapIdUnspecified

	ue.EstablishmentEnable()
	ue.PduSessionExtendedList = make(map[int64]*PDUSessionExtended)
	ue.PduSessionIDList = make(map[int64]bool)
	ue.PduSessionList = make(map[int64]*PDUSession)
	ue.AuthorizedQosRulesList = make(map[int64]types.AuthorizedQosRules)
	var pduSessionID int64
	for pduSessionID = 1; pduSessionID < 16; pduSessionID++ {
		ue.PduSessionIDList[pduSessionID] = false
	}
	ue.SM = make(map[types.RGType]*fsm.FSM)

	ue.RegistrationType = nasMessage.RegistrationType5GSInitialRegistration

	ue.BinarySemaphoreDeregistration = make(chan struct{}, 1)
	ue.BinarySemaphoreDeregistration <- struct{}{}
}

func (ue *UEContext) InitTimers() {
	// timer default values
	ue.T3502Value = DefaultT3502Value
	ue.T3510Value = DefaultT3510Value
	ue.T3511Value = DefaultT3511Value
	ue.T3517Value = DefaultT3517Value
	ue.T3521Value = DefaultT3521Value
	ue.T3525Value = DefaultT3525Value
	ue.T3540Value = DefaultT3540Value
	ue.T3580Value = DefaultT3580Value
	ue.T3582Value = DefaultT3582Value
	ue.MaxRegistrationRetryTime = MaxRegistrationRetryTime
	ue.MaxRegistrationAttemptTime = MaxRegistrationAttemptTime
	ue.MaxServiceAttemptTime = MaxServiceAttemptTime
	ue.MaxDeregistrationRetryTime = MaxDeregistrationRetryTime
	ue.Non3GppDeregistrationTimerValue = DefaultNon3GppDeregistrationTimerValue
	ue.MaxT3580RetryTimes = MaxT3580RetryTimes
	ue.MaxT3582RetryTimes = MaxT3582RetryTimes
}

// 24.501 9.11.3.4

func (ue *UEContext) InitMobileIdentity() {
	mobileIdentity := nasType.NewMobileIdentity5GS(0)
	var mobileIdentity5GSContents []uint8
	/*
	   Type of Identity
	   - 001: SUCI <===
	   - 010: 5G-GUTI
	   - 011: IMEI
	   - 100: 5G-S-TIMSI
	   - 101: IMEISV
	   - 110: MAC address <=== ??
	   - 111: EUI-64

	   SUPI Format: for SUCI
	   - 000: IMSI
	   - 001: Network specific identifier (NAI)
	   - 010: GCI
	   - 011: GLI <===
	*/
	if len(ue.LineID) != 0 {
		//8	7	6	5	4	3	2	1
		//	5GS mobile identity IEI					octet 1
		//	Length of contents  					octet 2
		//0	SUPI format             0       Type of identity	octet 3
		//	SUCI NAI 			     			octet 5-y
		//
		// NAI: type<supi type>.rid<routing indicator>.schid<protection scheme id>.userid<MSIN or Network Specific Identifier SUPI username>
		// SUPI:type2.rid0.schid0.userid<GLI>@5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org

		ue.SupiType = nasMessage.SupiFormatGLI                 // 0x03
		ue.IdentityType = nasMessage.MobileIdentity5GSTypeSuci // 0x01
		realm := "5gc.mnc" + "123" + ".mcc" + "123" + ".3gppnetwork.org"
		ue.Nai = fmt.Sprintf("type2.rid0.schid0.userid%s@%s", ue.GlobalIDStr, realm)

		mobileIdentity5GSContents = append(mobileIdentity5GSContents, 0x31)
		nai := StringToNgap(ue.Nai)
		for i := 0; i < len(nai); i++ {
			mobileIdentity5GSContents = append(mobileIdentity5GSContents, nai[i])
		}
		mobileIdentity.SetLen(uint16(len(mobileIdentity5GSContents)))
		mobileIdentity.SetMobileIdentity5GSContents(mobileIdentity5GSContents)
	} else if ue.MAC != "" {
		//8	7	6	5	4	3	2	1
		//	5GS mobile identity IEI					octet 1
		//	Length of contents  					octet 2
		//0	0       0       0       1       Type of identity	octet 3
		//	MAC address 			     			octet 5-10
		var mobileIdentity5GSContents []uint8
		ue.IdentityType = nasMessage.MobileIdentity5GSTypeMacAddress //0x06
		mobileIdentity5GSContents = append(mobileIdentity5GSContents, 0x0e)
		mac := StringToNgap(ue.MAC)
		if len(mac) != 6 {
			return
		}
		for i := 0; i < len(mac); i++ {
			mobileIdentity5GSContents = append(mobileIdentity5GSContents, mac[i])
		}
		mobileIdentity.SetLen(7)
		mobileIdentity.SetMobileIdentity5GSContents(mobileIdentity5GSContents)
	}
	if len(mobileIdentity5GSContents) > 0 {
		ue.MobileIdentity = mobileIdentity
	} else {
	}

	// Remove the identification procedure temporarily
	// Linked issue: https://jira.casa-systems.com/browse/GCS-832
	// if guti5G, ok := AGFSelf.LoadMobileIdentity5GSGUTI5GMAC(ue.MAC); ok {
	// 	ue.Guti = guti5G
	// }
}

func (ue *UEContext) InitNasSecurityCapability() {
	ue.CipheringAlg = security.AlgCiphering128NEA0 // null ciphering algorithm
	ue.IntegrityAlg = security.AlgIntegrity128NIA0 // null Integrity protection algorithm
	ue.SecurityHeaderType = nas.SecurityHeaderTypePlainNas

	// 0 - native security context(KSIamf), 1 - mapped security context(KSIasme)
	ue.NgKsi.Tsc = models.ScType_NATIVE
	// 0..6, 0x07 is no key available
	ue.NgKsi.Ksi = nasMessage.NasKeySetIdentifierNoKeyIsAvailable

	nasUESecurityCapability := nasType.NewUESecurityCapability(0x2e)
	nasUESecurityCapability.SetLen(2)
	nasUESecurityCapability.SetEA0_5G(1)
	nasUESecurityCapability.SetIA0_5G(1)
	ue.NasUESecurityCapability = nasUESecurityCapability
}

/*func (ue *UEContext) InitRequestedSliceInfo() {
	total := 0

	for _, supportedTAItemLocal := range AGFSelf.Info.SupportedTAList {
		for _, broadcastPLMNListLocal := range supportedTAItemLocal.PLMNs {
			for _, sliceSupportItemLocal := range broadcastPLMNListLocal.SLICES {
				// SliceSupportItem in SliceSupportList
				sst, _ := strconv.Atoi(sliceSupportItemLocal.SNSSAI.SST)
				snssai := models.Snssai{
					Sst: int32(sst),
					Sd:  sliceSupportItemLocal.SNSSAI.SD,
				}
				ue.RequestedNssai = append(ue.RequestedNssai, snssai)
				total++
				if total == 8 {
					break
				}
			}
		}
	}
}*/

/*func (ue *UEContext) GetSliceInfo() (string, *models.Snssai) {
	var dnn string
	var slice *models.Snssai
	for index := range ue.AllowedNssai {
		snssai := &ue.AllowedNssai[index]
		defaultDnn, backupDnn := AGFSelf.GetDnnForSlice(snssai)
		if defaultDnn != "" {
			return defaultDnn, snssai
		}
		if backupDnn != "" {
			dnn = backupDnn
			slice = snssai
		}
	}
	return dnn, slice
}*/

func (ue *UEContext) Remove() {
	// remove from AMF context
	ue.DetachAMF()

	// cleanup PDU session
	for _, pduSession := range ue.PduSessionList {
		if pduSession != nil {
			ue.PduSessionIDList[pduSession.Id] = false

			//AGFSelf.DeleteTEID(pduSession.GTPConnection.IncomingTEID)
			delete(ue.PduSessionList, pduSession.Id)
			ue.DeleteAuthorizedQosRule(pduSession.Id)

			//IncSessionDeleted()
			//ue.Stats.IncSessionDeleted(pduSession)
		} else {
		}
	}

	// Store UEException to AGFContext
	//AGFSelf.StoreUEExceptionContext(ue)

}

func (ue *UEContext) NewPDUSessionID() int64 {
	var pduSessionID int64
	for pduSessionID = 1; pduSessionID < 16; pduSessionID++ {
		if active, ok := ue.PduSessionIDList[pduSessionID]; ok {
			if !active {
				return pduSessionID
			}
		}
	}
	return 0
}

func (ue *UEContext) FindPDUSession(pduSessionID int64) *PDUSession {
	if pduSession, ok := ue.PduSessionList[pduSessionID]; ok {
		return pduSession
	} else {
		return nil
	}
}

func (ue *UEContext) CreatePDUSession(pduSessionID int64, snssai ngapType.SNSSAI) (*PDUSession, error) {
	if _, exists := ue.PduSessionList[pduSessionID]; exists {
		return nil, fmt.Errorf("PDU Session[ID:%d] already exists", pduSessionID)
	}

	pduSession := &PDUSession{
		Id:       pduSessionID,
		Snssai:   snssai,
		QosFlows: make(map[int64]*QosFlow),
	}
	ue.PduSessionIDList[pduSessionID] = true
	ue.PduSessionList[pduSessionID] = pduSession

	//IncSessionCreated()
	//ue.Stats.IncSessionCreated(pduSession)

	return pduSession, nil
}

func (ue *UEContext) DeletePDUSession(pduSessionID int64) error {
	if value := ue.LoadPduSessionIDList(uint8(pduSessionID)); value {
		ue.PduSessionIDList[pduSessionID] = false

		if pduSession := ue.FindPDUSession(pduSessionID); pduSession != nil {
			//AGFSelf.DeleteTEID(pduSession.GTPConnection.IncomingTEID)
			ue.StorePDUSessionExtendedStateCause(pduSessionID, PDUSessionStateReleased, "")
			delete(ue.PduSessionList, pduSessionID)
			ue.DeleteAuthorizedQosRule(pduSessionID)

			//IncSessionDeleted()
			//ue.Stats.IncSessionDeleted(pduSession)
		}

		return nil
	}

	return fmt.Errorf("PDUSession[ID:%d] does not exist", pduSessionID)
}

// EstablishmentEnable enables to send a PDU Session Establishment Request after receiving a PDU Session Establishment
// Request, PDU Session Establishment Accept or PDU Session Establishment Reject or after the T3580 expires
//
// Linked issue: https://gitlab.casa-systems.com/mobility/agf/agf-cp/-/issues/162
func (ue *UEContext) EstablishmentEnable() {
	ue.Establishing = false
}

// EstablishmentDisable disables to send the PDU Session Establishment Request repeatedly after a PDU Session
// Establishment Request has been sent
//
// Linked issue: https://gitlab.casa-systems.com/mobility/agf/agf-cp/-/issues/162
func (ue *UEContext) EstablishmentDisable() {
	ue.Establishing = true
}

// Establishment is used to determine whether a PDU Session Establishment Request is enabled to be sent
//
// Linked issue: https://gitlab.casa-systems.com/mobility/agf/agf-cp/-/issues/162
func (ue *UEContext) Establishment() bool {
	return !ue.Establishing
}

// LoadPduSessionExtended returns the pduSessionExtended stored in the map for a
// pduSessionID, or nil if no pduSessionExtended is present. The ok result indicates
// whether pduSessionExtended was found in the map.
func (ue *UEContext) LoadPduSessionExtended(pduSessionID int64) (pduSessionExtended *PDUSessionExtended, ok bool) {
	pduSessionExtended, ok = ue.PduSessionExtendedList[pduSessionID]
	return
}

// StorePDUSessionExtendedType sets the pduSessionType for a pduSessionID
func (ue *UEContext) StorePDUSessionExtendedType(pduSessionID int64, pduSessionType string) {
	if pduSessionExtended, ok := ue.LoadPduSessionExtended(pduSessionID); ok {
		pduSessionExtended.Type = pduSessionType
	} else {
		ue.PduSessionExtendedList[pduSessionID] = &PDUSessionExtended{Type: pduSessionType}
	}
}

// StorePDUSessionExtendedStateCause sets the pduSessionState and pduSessionCause for a pduSessionID
func (ue *UEContext) StorePDUSessionExtendedStateCause(pduSessionID int64, pduSessionState string, pduSessionCause string) {
	if pduSessionExtended, ok := ue.LoadPduSessionExtended(pduSessionID); ok {
		pduSessionExtended.State = pduSessionState
		pduSessionExtended.Cause = pduSessionCause
	} else {
		ue.PduSessionExtendedList[pduSessionID] = &PDUSessionExtended{State: pduSessionState, Cause: pduSessionCause}
	}
}

// EnableIntegrityProtection enables the integrity protection during encoding and decoding of NAS signalling messages
//
// TS 24.501 4.4.4.2 Integrity checking of NAS signalling messages in the UE
//
// Except the messages listed below, no NAS signalling messages shall be processed by the receiving 5GMM entity in the
// UE or forwarded to the 5GSM entity, unless the network has established secure exchange of 5GS NAS messages for the
// NAS signalling connection:
//
// a) IDENTITY REQUEST (if requested identification is SUCI); b) AUTHENTICATION REQUEST; c) AUTHENTICATION RESULT; d) AUTHENTICATION REJECT; e) REGISTRATION REJECT (if the 5GMM cause is not #76); f) DEREGISTRATION ACCEPT (for normal); and g) SERVICE REJECT (if the 5GMM cause is not #76).
//
// NOTE: These messages are accepted by the UE without integrity protection, as in certain situations they are sent by
// the network before security can be activated.
//
// TS 24.501 4.4.4.3 Integrity checking of NAS signalling messages in the AMF
//
// Except the messages listed below, no NAS signalling messages shall be processed by the receiving 5GMM entity in the
// AMF or forwarded to the 5GSM entity, unless the secure exchange of NAS messages has been established for the NAS
// signalling connection:
//
// a) REGISTRATION REQUEST; b) IDENTITY RESPONSE (if requested identification is SUCI); c) AUTHENTICATION RESPONSE; d) AUTHENTICATION FAILURE; e) SECURITY MODE REJECT; f) DEREGISTRATION REQUEST; and g) DEREGISTRATION ACCEPT.
//
// NOTE: These messages are accepted by the AMF without integrity protection, as in certain situations they are sent by
// the UE before security can be activated.
func (ue *UEContext) EnableIntegrityProtection() {
	ue.SecurityContextAvailable = true
}

// DisableIntegrityProtection disables the integrity protection during encoding and decoding of NAS signalling messages
func (ue *UEContext) DisableIntegrityProtection() {
	ue.SecurityContextAvailable = false
}

func (ue *UEContext) LoadPduSessionIDList(pduSessionID uint8) bool {
	if value, ok := ue.PduSessionIDList[int64(pduSessionID)]; ok {
		return value
	}

	return false
}

func (ue *UEContext) RGAttach(rgCtx *types.RGContext) {
	ue.RGType = rgCtx.RGType
	ue.MAC = rgCtx.MAC
	ue.CircuitID = rgCtx.CircuitID
	ue.RemoteID = rgCtx.RemoteID
	ue.WAgfInfo = rgCtx.WAgfInfo
	ue.LineType = rgCtx.LineType
	ue.AutoCreatePDUSession = rgCtx.CreatePDUSession
	ue.EstablishingPduSessionType = rgCtx.PDUSessionType
	ue.MacUnique = rgCtx.MacUnique

	ue.InitNasSecurityCapability()
	ue.InitTimers()
	ue.InitMobileIdentity()
	//ue.InitRequestedSliceInfo()
}

/*func (ue *UEContext) AttachAnyAMF() bool {
	if ue.CurrentAMF != nil {
		return true
	}

	amfContext := AGFSelf.AMFSelection(nil)
	if amfContext != nil {
		ue.CurrentAMFIndex = amfContext.SCTPAddr
		ue.CurrentAMF = amfContext
		return true
	}
	return false
}*/

func (ue *UEContext) AttachAMF(amf *AMFContext) {
	if ue.CurrentAMF != amf {
		ue.DetachAMF()
	}

	ue.CurrentAMFIndex = amf.SCTPAddr
	ue.CurrentAMF = amf
}

/*func (ue *UEContext) AttachAMFByAddr(sctpAddr string) bool {
	if amf, ok := AGFSelf.LoadAMFContextSCTPRemoteAddr(sctpAddr); ok {
		ue.CurrentAMFIndex = amf.SCTPAddr
		ue.CurrentAMF = amf

		return true
	} else {
		return false
	}
}*/

func (ue *UEContext) DetachAMF() {
	if ue.CurrentAMF == nil {
		return
	}

	ue.CurrentAMF.DeleteUEContextAMFUENGAPID(ue.AmfUeNgapId)
}

func (ue *UEContext) ChangeSmState(subsequentState fsm.State) error {
	if subsequentState == ue.SM[ue.RGType].Current() {
		return nil
	}

	ue.StateMachineIndex = subsequentState

	return ue.SM[ue.RGType].Transfer(subsequentState, nil)
}

func (ue *UEContext) SmState() string {
	return string(ue.SM[ue.RGType].Current())
}
func (ue *UEContext) RGTypeStr() string {
	return fmt.Sprintf("%s", ue.RGType)
}

/*func (ue *UEContext) RetryRegistration() bool {
	switch ue.SM[ue.RGType].Current() {
	case types.GMM_UE_CONTEXT_RELEASED:
	case types.GMM_EXCEPTION:
		return false
	default:
	}
	return true
}*/

func (ue *UEContext) GetPDUSessionStatus() *[16]bool {
	var pduSessionStatus *[16]bool
	pduSessionStatus = new([16]bool)
	for psi := 1; psi <= 15; psi++ {
		if _, exists := ue.PduSessionList[int64(psi)]; exists {
			pduSessionStatus[psi] = true
		}
	}
	return pduSessionStatus
}

func (ue *UEContext) StoreAuthorizedQosRule(pduSessionID int64, authorizedQosRule types.AuthorizedQosRules) {
	ue.AuthorizedQosRulesList[pduSessionID] = authorizedQosRule
}

func (ue *UEContext) LoadAuthorizedQosRule(pduSessionID int64) types.AuthorizedQosRules {
	return ue.AuthorizedQosRulesList[pduSessionID]
}

func (ue *UEContext) DeleteAuthorizedQosRule(pduSessionID int64) {
	delete(ue.AuthorizedQosRulesList, pduSessionID)
}

// LogTag is used to generate the tag based on the MAC and State Machine
func (ue *UEContext) LogTag(token string) string {
	if _, ok := ue.SM[ue.RGType]; ok {
		return token + "-" + ue.MAC + "-" + string(ue.SM[ue.RGType].Current())
	}

	return token + "-" + ue.MAC
}
func (ue *UEContext) SetAttached(status uint8) {
	if ue.Attached != status {
		ue.Attached = status
	}
}
func (ue *UEContext) ISAttached() bool {
	if ue.Attached > 0 {
		return true
	} else {
		return false
	}
}

func StringToNgap(str string) []byte {
	var x = []byte{}
	for i := 0; i < len(str); i++ {
		x = append(x, str[i])
	}
	return x
}
func AppendStringToNgap(x []byte, str string) []byte {
	for i := 0; i < len(str); i++ {
		x = append(x, str[i])
	}
	return x
}
func AppendNgapByte(x []byte, y []byte) []byte {
	for i := 0; i < len(y); i++ {
		x = append(x, y[i])
	}
	return x
}

// InitGlobalLineID initializes the LineID, GLI, GLIStr and GLISUPI according to the CircuitID and RemoteID
//
// - Global Line Identifier
//
// <-     5      -> <- up to 130 ->
//
// | Global AGF ID |    Line ID    |
//
// - Line Identifier
//
//  <-1 -> <- 1  -> <-  1-63  ->          <-1 -> <- 1  -> <- 1-63  ->
//
// | 0x01 | Length | Circuit ID | and/or | 0x02 | Length | Remote ID |
func InitGlobalLineID(srcMAC string, srcLineID []byte, srcCircuitID string, srcRemoteID string) ([]byte, aper.OctetString, string, string) {
	var tgtGLI aper.OctetString
	var tgtGLIStr, tgtGLISUPI string
	// AGF Operator Administered Source ID - Permissible values 0x30-0x39
	lineIDSource := fmt.Sprintf("%05d", 77)
	gli := StringToNgap(lineIDSource)

	if len(srcLineID) == 0 {
		var lineID []byte
		var gliSUPI string

		if srcCircuitID != "" {
			lineID = append(lineID, 0x01)
			lineID = append(lineID, byte(len(srcCircuitID)))
			// Permissible values 0x20-0x7e
			lineID = AppendStringToNgap(lineID, srcCircuitID)
			gliSUPI = fmt.Sprintf("%s1%x", gliSUPI, srcCircuitID)
		}
		if srcRemoteID != "" {
			lineID = append(lineID, 0x02)
			lineID = append(lineID, byte(len(srcRemoteID)))
			// Permissible values 0x20-0x7e
			lineID = AppendStringToNgap(lineID, srcRemoteID)
			gliSUPI = fmt.Sprintf("%s2%x", gliSUPI, srcRemoteID)
		}

		srcLineID = lineID
		tgtGLISUPI = lineIDSource + gliSUPI
	} else {
		var components [][]byte

		for key, value := range srcLineID[2:] {
			if value == 0x02 {
				components = append(components, srcLineID[2:key+2])
				components = append(components, srcLineID[key+4:])

				tgtGLISUPI = lineIDSource + fmt.Sprintf("1%x", components[0]) + fmt.Sprintf("2%x", components[1])
				break
			}
		}

		if len(components) == 0 {
			tgtGLISUPI = lineIDSource + fmt.Sprintf("%d%x", srcLineID[0], srcLineID[2:])
		}
	}

	gli = AppendNgapByte(gli, srcLineID)
	tgtGLIStr = base64.StdEncoding.EncodeToString(gli)
	tgtGLI = StringToNgap(tgtGLIStr)

	base64.StdEncoding.DecodeString(tgtGLIStr)

	return srcLineID, tgtGLI, tgtGLIStr, tgtGLISUPI
}
