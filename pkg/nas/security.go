package nas

import (
	"fmt"
	"free5gc/lib/nas"
	"free5gc/lib/nas/security"
	"reflect"

	"sim-amf/pkg/context"
	"sim-amf/pkg/types"
)

func Encode(ue *context.UEContext, msg *nas.Message, newSecurityContext bool) (payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("UEContext is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas Message is empty")
		return
	}

	if !ue.SecurityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.ULCount.GetSQN()

		payload, err = msg.PlainNasEncode()
		if err != nil {
			return
		}

		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), security.Bearer3GPP, security.DirectionDownlink, payload); err != nil {
			return
		}

		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		var mac32 []byte
		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), security.Bearer3GPP, security.DirectionDownlink, payload)
		if err != nil {
			return
		}
		if mac32 == nil {
			mac32 = []byte{0x00, 0x00, 0x0, 0x00}
		}

		// Add mac value
		payload = append(mac32, payload[:]...)

		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)
		// Increase DL Count
		ue.ULCount.AddOne()
	}
	return
}

/*
payload either a security protected 5GS NAS message or a plain 5GS NAS message which
format is followed TS 24.501 9.1.1
*/
func Decode(ue *context.UEContext, rgType types.RGType, securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {

	if ue == nil {
		err = fmt.Errorf("UEContext is nil")
		return
	}
	if payload == nil {
		err = fmt.Errorf("Nas payload is empty")
		return
	}

	msg = new(nas.Message)
	msg.SecurityHeaderType = securityHeaderType
	if securityHeaderType == nas.SecurityHeaderTypePlainNas {
		err = msg.PlainNasDecode(&payload)
		ue.MacFailed = false
		return
	} else { // security protected NAS message
		securityHeader := payload[0:6]
		sequenceNumber := payload[6]

		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		if securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext || securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
			ue.DLCount.Set(0, 0)
		}

		if ue.DLCount.GetSQN() > sequenceNumber {
			ue.DLCount.SetOverflow(ue.DLCount.GetOverflow() + 1)
		}
		ue.DLCount.SetSQN(sequenceNumber)

		if ue.SecurityContextAvailable {
			mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.DLCount.Get(), security.Bearer3GPP,
				security.DirectionUplink, payload)
			if err != nil {
				ue.MacFailed = true
			}
			if mac32 == nil {
				mac32 = []byte{0x00, 0x00, 0x0, 0x00}
			}

			if !reflect.DeepEqual(mac32, receivedMac32) {
				ue.MacFailed = true
			} else {
				ue.MacFailed = false
			}

			// TODO: Support for ue has nas connection in both accessType
			if securityHeaderType != nas.SecurityHeaderTypeIntegrityProtected {
				// decrypt payload without sequence number (payload[1])
				if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount.Get(), security.Bearer3GPP, security.DirectionUplink, payload[1:]); err != nil {
					return nil, err
				}
			}
		} else {
			ue.MacFailed = true
		}

		// remove sequece Number
		payload = payload[1:]
		err = msg.PlainNasDecode(&payload)
	}
	return
}
