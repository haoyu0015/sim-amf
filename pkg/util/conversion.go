package util

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"free5gc/lib/aper"
	"free5gc/lib/nas/nasConvert"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/ngap/ngapConvert"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"strings"
)

// TS 24.008 Table 10.5.163: GPRS Timer 2 information element
//
// Bits 6 to 8 defines the timer value unit for the GPRS timer
const (
	SecondsPerMinute   int = 60
	SecondsPerHour     int = SecondsPerMinute * 60
	SecondsPerDecihour int = SecondsPerHour / 10

	GPRSTimer2UintMask  uint8 = ^GPRSTimer2ValueMask
	GPRSTimer2ValueMask uint8 = (0x01 << 5) - 1

	GPRSTimer2UintIncrementedInMultiplesOf2Seconds  uint8 = 0x00 << 5
	GPRSTimer2UintIncrementedInMultiplesOf1Minute   uint8 = 0x01 << 5
	GPRSTimer2UintIncrementedInMultiplesOfDecihours uint8 = 0x02 << 5
	GPRSTimer2UintDeactivated                       uint8 = 0x07 << 5
)

func PlmnIdToNgap(pmcc string, pmnc string) (ngapPlmnId ngapType.PLMNIdentity) {
	var hexString string
	mcc := strings.Split(pmcc, "")
	mnc := strings.Split(pmnc, "")
	if len(mnc) == 2 {
		hexString = mcc[1] + mcc[0] + "f" + mcc[2] + mnc[1] + mnc[0]
	} else {
		hexString = mcc[1] + mcc[0] + mnc[0] + mcc[2] + mnc[2] + mnc[1]
	}
	ngapPlmnId.Value, _ = hex.DecodeString(hexString)
	return
}

func N3iwfIdToNgap(n3iwfId uint16) (ngapN3iwfId *aper.BitString) {
	ngapN3iwfId = new(aper.BitString)
	ngapN3iwfId.Bytes = make([]byte, 2)
	binary.BigEndian.PutUint16(ngapN3iwfId.Bytes, n3iwfId)
	ngapN3iwfId.BitLength = 16
	return
}

func GnbIdToNgap(gnbId uint32) (ngapN3iwfId *aper.BitString) {
	ngapN3iwfId = new(aper.BitString)
	ngapN3iwfId.Bytes = make([]byte, 4)
	binary.BigEndian.PutUint32(ngapN3iwfId.Bytes, gnbId)
	ngapN3iwfId.BitLength = 32
	return
}

func Uint8ToNgap(val uint8) (ngapId *aper.BitString) {
	ngapId = new(aper.BitString)
	ngapId.Bytes = make([]byte, 1)
	ngapId.Bytes[0] = val
	ngapId.BitLength = 8
	return
}

func Uint16ToNgap(val uint16) (ngapId *aper.BitString) {
	ngapId = new(aper.BitString)
	ngapId.Bytes = make([]byte, 2)
	binary.BigEndian.PutUint16(ngapId.Bytes, val)
	ngapId.BitLength = 16
	return
}

func Uint32ToNgap(val uint32) (ngapVal *aper.BitString) {
	ngapVal = new(aper.BitString)
	ngapVal.Bytes = make([]byte, 4)
	binary.BigEndian.PutUint32(ngapVal.Bytes, val)
	ngapVal.BitLength = 32
	return
}

func Uint64ToNgap(val uint64) (ngapVal *aper.BitString) {
	ngapVal = new(aper.BitString)
	ngapVal.Bytes = make([]byte, 16)
	binary.BigEndian.PutUint64(ngapVal.Bytes, val)
	ngapVal.BitLength = 64
	return
}

func StringToNgap(str string) []byte {
	var x = []byte{}
	for i := 0; i < len(str); i++ {
		x = append(x, str[i])
	}
	return x
}

func NasAllowedNssaiToModels(nasNssai *nasType.AllowedNSSAI) (nssai []models.Snssai) {

	buf := nasNssai.GetSNSSAIValue()
	lengthOfBuf := int(nasNssai.GetLen())
	offset := 0
	total := 0
	for offset < lengthOfBuf {
		snssaiValue := buf[offset:]
		snssai, readLength := NasSnssaiToModels(snssaiValue)
		nssai = append(nssai, snssai)
		offset += readLength
		total++
		if total == 8 {
			break
		}
	}

	return

}

func NasConfiguredNssaiToModels(nasNssai *nasType.ConfiguredNSSAI) (nssai []models.Snssai) {

	buf := nasNssai.GetSNSSAIValue()
	lengthOfBuf := int(nasNssai.GetLen())
	offset := 0
	total := 0
	for offset < lengthOfBuf {
		snssaiValue := buf[offset:]
		snssai, readLength := NasSnssaiToModels(snssaiValue)
		nssai = append(nssai, snssai)
		offset += readLength
		total++
		if total == 16 {
			break
		}
	}

	return
}

func NasRejectedNssaiToModels(nasNssai *nasType.RejectedNSSAI) (nssaiInPlmn []models.Snssai, nssaiInTai []models.Snssai) {

	buf := nasNssai.GetRejectedNSSAIContents()
	lengthOfBuf := int(nasNssai.GetLen())
	offset := 0
	total := 0
	for offset < lengthOfBuf {
		snssaiValue := buf[offset:]
		snssai, readLength, cause := NasRejectedSnssaiToModels(snssaiValue)
		switch cause {
		case nasMessage.RejectedSnssaiCauseNotAvailableInCurrentPlmn:
			nssaiInPlmn = append(nssaiInPlmn, snssai)
		case nasMessage.RejectedSnssaiCauseNotAvailableInCurrentRegistrationArea:
			nssaiInTai = append(nssaiInTai, snssai)
		}
		offset += readLength
		total++
		if total == 8 {
			break
		}
	}

	return

}

func NgapAllowedNssaiToModels(ngapNssai *ngapType.AllowedNSSAI) (nssai []models.Snssai) {
	for _, item := range ngapNssai.List {
		snssai := ngapConvert.SNssaiToModels(item.SNSSAI)
		nssai = append(nssai, snssai)
	}

	return
}

func NasSnssaiToModels(buf []byte) (snssai models.Snssai, length int) {

	lengthOfSnssaiContents := buf[0]
	switch lengthOfSnssaiContents {
	case 0x01: // sst
		snssai.Sst = int32(buf[1])
		length = 2
	case 0x04: // sst + sd
		snssai.Sst = int32(buf[1])
		snssai.Sd = hex.EncodeToString(buf[2:5])
		length = 5
	default:
		fmt.Printf("Not Supported length in snssai: %d\n", lengthOfSnssaiContents)
	}

	return
}

func NasRejectedSnssaiToModels(buf []byte) (snssai models.Snssai, length int, cause uint8) {
	lengthOfBuf := len(buf)
	lengthOfSnssaiContents := buf[0] >> 4
	cause = buf[0] & 0x0f
	switch lengthOfSnssaiContents {
	case 0x01: // sst
		snssai.Sst = int32(buf[1])
		length = 2
	case 0x02, 0x03, 0x04: // sst + sd
		snssai.Sst = int32(buf[1])
		offset := int(lengthOfSnssaiContents) + 1
		if offset >= lengthOfBuf {
			snssai.Sd = hex.EncodeToString(buf[2:offset])
		} else {
			snssai.Sd = hex.EncodeToString(buf[2:])
		}
		length = offset
	default:
		fmt.Printf("Not Supported length in snssai: %d cause:%d\n", lengthOfSnssaiContents, cause)
	}

	return
}

func NasTaiListToModels(nasTais *nasType.TAIList) (tais []models.Tai) {

	buf := nasTais.GetPartialTrackingAreaIdentityList()
	typeOfList := buf[0] >> 5
	numOfElementsNas := buf[0]&0x1f + 1
	lengthOfContents := len(buf)

	switch typeOfList {
	case 0x00:
		plmnIdStr := nasConvert.PlmnIDToString(buf[1:4])
		PlmnId := new(models.PlmnId)
		PlmnId.Mcc = plmnIdStr[:3]
		PlmnId.Mnc = plmnIdStr[3:]
		offset := 4
		for offset < lengthOfContents {
			if offset+4 > lengthOfContents {
				tai := models.Tai{
					PlmnId: PlmnId,
					Tac:    hex.EncodeToString(buf[offset:]),
				}
				tais = append(tais, tai)
			} else {
				tai := models.Tai{
					PlmnId: PlmnId,
					Tac:    hex.EncodeToString(buf[offset : offset+4]),
				}
				tais = append(tais, tai)
			}
			offset += 3
		}
	case 0x01:
	case 0x02:
	default:
		fmt.Printf("Not Supported type of tai list: %d numOfElem: %d\n", typeOfList, numOfElementsNas)
	}
	return
}

// GUTI5GToMobileIdentity5GS converts GUTI5G to MobileIdentity5GS
func GUTI5GToMobileIdentity5GS(guti5G nasType.GUTI5G) *nasType.MobileIdentity5GS {
	mobileIdentity5GS := &nasType.MobileIdentity5GS{}

	mobileIdentity5GS.Iei = guti5G.Iei
	mobileIdentity5GS.Len = guti5G.Len
	mobileIdentity5GS.Buffer = make([]uint8, len(guti5G.Octet))
	copy(mobileIdentity5GS.Buffer[:], guti5G.Octet[:])

	return mobileIdentity5GS
}

// GPRSTimer2ContentToSeconds converts GPRS Timer 2 Content to seconds
//
// TS 24.008 10.5.7.4 GPRS Timer 2
func GPRSTimer2ContentToSeconds(content uint8) int {
	switch content & GPRSTimer2UintMask {
	case GPRSTimer2UintIncrementedInMultiplesOf2Seconds:
		return int(content&GPRSTimer2ValueMask) * 2
	case GPRSTimer2UintIncrementedInMultiplesOfDecihours:
		return int(content&GPRSTimer2ValueMask) * SecondsPerDecihour
	case GPRSTimer2UintDeactivated:
		return 0
	case GPRSTimer2UintIncrementedInMultiplesOf1Minute:
		fallthrough
		// Other values shall be interpreted as multiples of 1 minute in this version of the protocol.
	default:
		return int(content&GPRSTimer2ValueMask) * SecondsPerMinute
	}
}
