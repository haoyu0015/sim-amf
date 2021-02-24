package main

import (
	"free5gc/lib/aper"
	lib_nas "free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	lib_ngap "free5gc/lib/ngap"
	"free5gc/lib/ngap/ngapType"
	"sim-amf/pkg/logger"
	"sim-amf/pkg/nas"
	"sim-amf/pkg/types"
	"sim-amf/pkg/util"
	"sync"

	"sim-amf/pkg/context"

	"github.com/davecgh/go-spew/spew"
	"gitlab.casa-systems.com/opensource/sctp"
)

const NGAPPPIDBigEndian = 0x3c000000

var SctpServerConn struct {
	lock        sync.Mutex
	sctpSrvConn *sctp.SCTPConn
}
var SctpListener struct {
	lock     sync.Mutex
	listener *sctp.SCTPListener
}
var SctpClientConn struct {
	lock        sync.Mutex
	sctpCliConn *sctp.SCTPConn
}

var RanIDAmfIDMap sync.Map

// var AMFUENGAPIDGenerator *types.IDGenerator

func main() {
	// ngap server listener
	addr, _ := sctp.ResolveSCTPAddr("sctp", "127.0.0.1:38412")
	listener, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		logger.MainLog.Error("Listen failed: %s", err)
	}

	// ngap client listener
	// go end2end_clientRoutine(t)

	// server accept connection
	serverConn, xerr := listener.AcceptSCTP()
	if xerr != nil {
		logger.MainLog.Error("Accept failed: %s", xerr)
	}
	info, err := serverConn.GetDefaultSentParam()
	if err != nil {
		logger.MainLog.Error("GetDefaultSentParam(): %+v", err)
		serverConn.Close()
		return
	}
	info.PPID = NGAPPPIDBigEndian
	err = serverConn.SetDefaultSentParam(info)
	if err != nil {
		logger.MainLog.Error("SetDefaultSentParam(): %+v", err)
		serverConn.Close()
		return
	}

	SetSctpServerConn(serverConn)
	SetSctpListener(listener)

	//var end2endWg sync.WaitGroup
	for {
		msg, err := ReadData(serverConn, "Server")
		if err != nil {
			logger.MainLog.Error("read failed: %v", err)
		} else {
			pdu, err := lib_ngap.Decoder(msg)
			if err != nil {
				logger.MainLog.Error("Server NGAP decode error: %+v", err)
				return
			}
			go func() {
				ue := InitTest()
				end2end_serverHandler(serverConn, pdu, ue)
			}()
		}
	}
}

func SetSctpServerConn(svr *sctp.SCTPConn) {
	SctpServerConn.lock.Lock()
	SctpServerConn.sctpSrvConn = svr
	SctpServerConn.lock.Unlock()
}

func SetSctpListener(lis *sctp.SCTPListener) {
	SctpListener.lock.Lock()
	SctpListener.listener = lis
	SctpListener.lock.Unlock()
}

func ReadData(conn *sctp.SCTPConn, info string) ([]byte, error) {
	msg := make([]byte, 65535)
	n, sctpInfo, err := conn.SCTPRead(msg)
	if err != nil {
		return msg, err
	} else {
		logger.MainLog.Debug("%s: read %d bytes successfully", info, n)
		if sctpInfo == nil {
			logger.MainLog.Debug("No SctpInfo")
		} else if sctpInfo.PPID != NGAPPPIDBigEndian {
			logger.MainLog.Warn("Received SCTP PPID = %v", sctpInfo.PPID)
		}

		return msg, err
	}
}

func SendData(conn *sctp.SCTPConn, pkt []byte, info string) (int, error) {
	var n int
	var err error
	if n, err = conn.Write(pkt); err != nil {
		logger.MainLog.Error("%s: write to SCTP socket failed: %+v", info, err)
	} else {
		logger.MainLog.Debug("[%s: wrote %d bytes successfully", info, n)
	}
	return n, err
}

func SendToAmf(amf *context.AMFContext, pkt []byte) {
	if amf == nil {
		logger.MainLog.Error("[NGAP] AMF Context is nil")
		return
	}
	if amf.SCTPConn == nil {
		logger.MainLog.Error("[NGAP] SCTP Connection is nil")
		return
	}
	if n, err := amf.SCTPConn.Write(pkt); err != nil {
		logger.MainLog.Error("[NGAP] Write to SCTP socket failed: %+v", err)
	} else {
		logger.MainLog.Debug("[NGAP] Wrote %d bytes", n)
	}
}

func DumpPdu(pdu *ngapType.NGAPPDU, info string) {
	logger.MainLog.Debug("DUMP start: %s", info)
	spew.Dump(pdu)
	logger.MainLog.Debug("DUMP end: %s", info)
}

func InitTest() *context.UEContext {
	// AMFUENGAPIDGenerator = types.NewIDGenerator(0, math.MaxInt64)
	ue := &context.UEContext{}
	InitTestUe(ue)

	return ue
}

func InitTestUe(ue *context.UEContext) {
	// init
	rgCtx := &types.RGContext{
		RGType:           types.RGType_FN_RG,
		MAC:              "02:42:d5:32:74:11",
		CircuitID:        "987",
		RemoteID:         "4567",
		LineType:         "PON",
		CreatePDUSession: false,
		MacUnique:        true,
	}

	ue.LineID, ue.GlobalID, ue.GlobalIDStr, ue.GlobalIDSUPI = context.InitGlobalLineID(
		rgCtx.MAC,
		context.StringToNgap(rgCtx.LineID),
		rgCtx.CircuitID,
		rgCtx.RemoteID)
	ue.Init()
	ue.RGAttach(rgCtx)

	ue.AmfUeNgapId = 999

	ue.Kwagf = []uint8{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	// overwrite timer default values fo test
	ue.T3502Value = 2
	ue.T3510Value = 1
	ue.T3511Value = 1
	ue.T3517Value = 1
	ue.T3521Value = 1
	ue.T3525Value = 1
	ue.T3540Value = 1
	ue.Non3GppDeregistrationTimerValue = 1

	ue.MaxRegistrationRetryTime = 1
	ue.MaxRegistrationAttemptTime = 2
	ue.ServiceType = nasMessage.ServiceTypeSignalling
}

func end2end_serverHandler(serverConn *sctp.SCTPConn, pdu *ngapType.NGAPPDU, ue *context.UEContext) {
	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		initiatingMessage := pdu.InitiatingMessage
		if initiatingMessage == nil {
			logger.MainLog.Error("Initiating Message is nil")
		}
		switch initiatingMessage.ProcedureCode.Value {
		case ngapType.ProcedureCodeNGSetup:
			handleNGSetupRequest(serverConn)
		case ngapType.ProcedureCodeInitialUEMessage:
			handleInitialUEMessage(pdu, ue, serverConn)
		case ngapType.ProcedureCodeUplinkNASTransport:
			handleUplinkNASTransport(pdu, ue, serverConn)
		case ngapType.ProcedureCodeUEContextReleaseRequest:
		default:
			logger.MainLog.Error("Not implemented NGAP message(initiatingMessage), procedureCode:%d", initiatingMessage.ProcedureCode.Value)
		}
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		successfulOutcome := pdu.SuccessfulOutcome
		if successfulOutcome == nil {
			logger.MainLog.Error("SuccessfulOutcome is nil")
		}
		switch successfulOutcome.ProcedureCode.Value {
		case ngapType.ProcedureCodeInitialContextSetup:
			switch successfulOutcome.Value.Present {
			case ngapType.SuccessfulOutcomePresentInitialContextSetupResponse:
				handleInitialContextSetupResponse(pdu, ue, serverConn)
			default:
				logger.MainLog.Error("[TEST] Server unexpected successfulOutcome(InitialContextSetup) response:%d", successfulOutcome.Value.Present)
			}
		case ngapType.ProcedureCodePDUSessionResourceSetup:
		case ngapType.ProcedureCodePDUSessionResourceRelease:
		case ngapType.ProcedureCodeUEContextRelease:
		default:
			logger.MainLog.Error("Server unexpected successfulOutcome procedure:%d", successfulOutcome.ProcedureCode.Value)
		}
	default:
		logger.MainLog.Error("Server Not implemented NGAP message, Present:%d", pdu.Present)

	}
}

func handleInitialUEMessage(pdu *ngapType.NGAPPDU, ue *context.UEContext, serverConn *sctp.SCTPConn) {
	initiatingMessage := pdu.InitiatingMessage
	switch initiatingMessage.Value.Present {
	case ngapType.InitiatingMessagePresentInitialUEMessage:
		initialUEMessage := initiatingMessage.Value.InitialUEMessage
		for i := 0; i < len(initialUEMessage.ProtocolIEs.List); i++ {
			ie := initialUEMessage.ProtocolIEs.List[i]
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDRANUENGAPID:
				ue.RanUeNgapId = ie.Value.RANUENGAPID.Value
			case ngapType.ProtocolIEIDNASPDU:
				nASPDU := ie.Value.NASPDU
				if nASPDU == nil {
					logger.MainLog.Error("Missing nasPDU")
				}
				nasPdu := nASPDU.Value
				msg, err := nas.Decode(ue, ue.RGType, lib_nas.GetSecurityHeaderType(nasPdu)&0x0f, nasPdu)
				if err != nil {
					logger.MainLog.Error("failed to decode NAS PDU")
				}
				if msg.GmmMessage == nil {
					logger.MainLog.Error("Missing gmm message in nasPdu")
				}
				switch msg.GmmMessage.GetMessageType() {
				case lib_nas.MsgTypeRegistrationRequest:
					pkt, err := BuildSecurityModeCommand(ue)
					if err != nil {
						logger.MainLog.Error("Error %v", err)
					}
					_, err = SendData(serverConn, pkt, "Server")
					if err != nil {
						logger.MainLog.Error("Error %v", err)
					}
				default:
					logger.MainLog.Error("Unexpected message in NASPDU(InitialUEMessage)")
				}
			default:
				logger.MainLog.Info("Server Recvd IE(InitialUEMessage) %d", ie.Id.Value)
			}
		}
	}
}

func handleNGSetupRequest(serverConn *sctp.SCTPConn) {
	pdu, err := sendNGSetupResponse()
	if err != nil {
		logger.MainLog.Error("Error %v", err)
	}
	_, err = SendData(serverConn, pdu, "Server")
}

func sendNGSetupResponse() ([]byte, error) {
	amfName := "TestAMF1"

	var guamiList []ngapType.ServedGUAMIItem
	servedGUAMIItem := ngapType.ServedGUAMIItem{}
	servedGUAMIItem.GUAMI.PLMNIdentity = util.PlmnIdToNgap("207", "90")
	servedGUAMIItem.GUAMI.AMFRegionID.Value = aper.BitString{
		Bytes:     []byte{0x45, 0x46, 0x47},
		BitLength: 8,
	}
	servedGUAMIItem.GUAMI.AMFSetID.Value = aper.BitString{
		Bytes:     []byte{0x45, 0x46, 0x47},
		BitLength: 8,
	}
	servedGUAMIItem.GUAMI.AMFPointer.Value = aper.BitString{
		Bytes:     []byte{0x45, 0x46, 0x47},
		BitLength: 6,
	}
	guamiList = append(guamiList, servedGUAMIItem)

	plmnList := []ngapType.PLMNSupportItem{
		{
			PLMNIdentity: util.PlmnIdToNgap("207", "90"),
			SliceSupportList: ngapType.SliceSupportList{
				List: []ngapType.SliceSupportItem{
					{
						SNSSAI: ngapType.SNSSAI{
							SST: ngapType.SST{
								Value: []byte{1},
							},
							SD: &ngapType.SD{
								Value: []byte{1, 2, 3},
							},
						},
					},
					{
						SNSSAI: ngapType.SNSSAI{
							SST: ngapType.SST{
								Value: []byte{1},
							},
							SD: &ngapType.SD{
								Value: []byte{0x11, 0x22, 0x33},
							},
						},
					},
				},
			},
		},
	}

	pdu := buildNGSetupResponse(amfName, guamiList, plmnList, 200)

	return lib_ngap.Encoder(pdu)
}

func handleUplinkNASTransport(pdu *ngapType.NGAPPDU, ue *context.UEContext, serverConn *sctp.SCTPConn) {
	initiatingMessage := pdu.InitiatingMessage
	uplinkNasTransport := initiatingMessage.Value.UplinkNASTransport
	for i := 0; i < len(uplinkNasTransport.ProtocolIEs.List); i++ {
		ie := uplinkNasTransport.ProtocolIEs.List[i]
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDRANUENGAPID:
			ue.RanUeNgapId = ie.Value.RANUENGAPID.Value
		case ngapType.ProtocolIEIDNASPDU:
			nASPDU := ie.Value.NASPDU
			if nASPDU == nil {
				logger.MainLog.Error("Missing nasPDU")
			}

			nasPdu := nASPDU.Value
			securityHeaderType := lib_nas.GetSecurityHeaderType(nasPdu) & 0x0f
			msg, err := nas.Decode(ue, ue.RGType, securityHeaderType, nasPdu)
			if err != nil {
				logger.MainLog.Error("Server failed to decode NAS PDU")
			}
			if msg.GmmMessage == nil {
				logger.MainLog.Error("Missing gmm message in nasPdu")
			}
			switch msg.GmmMessage.GetMessageType() {
			case lib_nas.MsgTypeSecurityModeComplete:
				pkt, err := BuildInitialContextSetupRequest(ue, nil)
				if err != nil {
					logger.MainLog.Error("Error %v", err)
				}
				_, err = SendData(serverConn, pkt, "Server")
				if err != nil {
					logger.MainLog.Error("Error %v", err)
				}
			case lib_nas.MsgTypeRegistrationComplete:

			case lib_nas.MsgTypeULNASTransport:
				end2end_handleGMMMsgULNASTransport(serverConn, ue, msg.GmmMessage.ULNASTransport, securityHeaderType)
			case lib_nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			/*pkt, err := BuildDeregistrationAccept(ue)
			if err != nil {
				logger.MainLog.Error("Error %v", err)
			}
			_, err = SendData(serverConn, pkt, "Server")
			if err != nil {
				logger.MainLog.Error("Error %v", err)
			}
			time.Sleep(1 * time.Second)
			// !!! client send !!!
			SendUEContextReleaseRequest(ue.CurrentAMF, ue, end2end_causePresent, end2end_causeValue)*/
			default:
				logger.MainLog.Error("[TEST] Unexpected message %v in NASPDU(UplinkNASTransport", msg.GmmMessage.GetMessageType())
			}
		default:
			logger.MainLog.Info("Server Recvd IE(UplinkNASTransport) %d", ie.Id.Value)
		}
	}
}

func end2end_handleGMMMsgULNASTransport(serverConn *sctp.SCTPConn, ue *context.UEContext, uLNASTransport *nasMessage.ULNASTransport, securityHeaderType uint8) {
	switch uLNASTransport.GetPayloadContainerType() {
	case nasMessage.PayloadContainerTypeN1SMInfo:
		m := lib_nas.NewMessage()
		err := m.GsmMessageDecode(&uLNASTransport.PayloadContainer.Buffer)
		if err != nil {
			logger.MainLog.Error("[TEST] faild to decode GSM message")
			return
		}
		messageType := m.GsmMessage.GetMessageType()

		// The UE shall include Request Type IE when the PDU session ID IE is included and
		// the Payload container IE contains the PDU SESSION ESTABLISHMENT REQUEST message or
		// the PDU SESSION MODIFICATION REQUEST.
		if messageType != lib_nas.MsgTypePDUSessionReleaseRequest && messageType != lib_nas.MsgTypePDUSessionReleaseComplete {
			requestType := uLNASTransport.GetRequestTypeValue()
			if requestType != nasMessage.ULNASTransportRequestTypeInitialRequest {
				logger.MainLog.Error("[TEST] Unexpected RequestType %v in NAS.UplinkNASTransport", requestType)
				return
			}
		}

		switch messageType {
		case lib_nas.MsgTypePDUSessionEstablishmentRequest:
			pduSessionID := uLNASTransport.GetPduSessionID2Value()
			pkt, err := BuildPDUSessionResourceSetupRequest(ue, pduSessionID)
			if err != nil {
				logger.MainLog.Error("Error %v", err)
			}
			_, err = SendData(serverConn, pkt, "Server")
			if err != nil {
				logger.MainLog.Error("Error %v", err)
			}
		case lib_nas.MsgTypePDUSessionReleaseRequest:
			// pduSession id hard code now, need to get it from message or ue context.
			pkt, err := BuildPDUSessionResourceReleaseCommand(ue, 1)
			if err == nil {
				SendData(serverConn, pkt, "Server")
			}
		case lib_nas.MsgTypePDUSessionReleaseComplete:
			// !!! client send !!!
			SendDeregistrationRequest(ue, 1)
		default:
			logger.MainLog.Error("[TEST] Unexpected GsmMessage[%d]\n", messageType)
		}
	}
}

func SendDeregistrationRequest(ue *context.UEContext, switchOff uint8) {
	nasMsg, err := BuildDeregistrationRequest(ue, switchOff, false)
	if err != nil {
		logger.MainLog.Error(err.Error())
		return
	}

	SendUplinkNASTransport(ue.CurrentAMF, ue, nasMsg)
}

func SendUplinkNASTransport(amf *context.AMFContext, ue *context.UEContext, nasPdu []byte) {
	if len(nasPdu) == 0 {
		logger.MainLog.Error("NAS Pdu is nil")
		return
	}

	pkt, err := BuildUplinkNASTransport(ue, nasPdu)
	if err != nil {
		logger.MainLog.Error("Build Uplink NAS Transport failed : %+v", err)
		return
	}

	SendToAmf(amf, pkt)
}

func handleInitialContextSetupResponse(pdu *ngapType.NGAPPDU, ue *context.UEContext, serverConn *sctp.SCTPConn) {
	initialContextSetupRsp := pdu.SuccessfulOutcome.Value.InitialContextSetupResponse
	for i := 0; i < len(initialContextSetupRsp.ProtocolIEs.List); i++ {
		ie := initialContextSetupRsp.ProtocolIEs.List[i]
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDRANUENGAPID:
			ue.RanUeNgapId = ie.Value.RANUENGAPID.Value
		}
	}
	pkt, err := BuildRegistrationAccept(ue)
	if err != nil {
		logger.MainLog.Error("[TEST] Error %v", err)
	}
	_, err = SendData(serverConn, pkt, "Server")
	if err != nil {
		logger.MainLog.Error("[TEST] Error %v", err)
	}
}
