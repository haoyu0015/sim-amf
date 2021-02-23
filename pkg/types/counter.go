package types

// TS 33.501 6.4.3.1
//
// COUNT (32 bits) := 0x00 || NAS COUNT (24 bits)
//
// NAS COUNT (24 bits) := NAS OVERFLOW (16 bits) || NAS SQN (8 bits)
type Count struct {
	Count uint32
}

func (counter *Count) MaskTo24Bits() {
	counter.Count &= 0x00ffffff
}

func (counter *Count) Set(overflow uint16, sqn uint8) {
	counter.SetOverflow(overflow)
	counter.SetSQN(sqn)
}

func (counter *Count) Get() uint32 {
	return counter.Count
}

func (counter *Count) AddOne() {
	counter.Count++
	counter.MaskTo24Bits()
}

func (counter *Count) GetSQN() uint8 {
	return uint8(counter.Count & 0x000000ff)
}

func (counter *Count) SetSQN(sqn uint8) {
	counter.Count = (counter.Count & 0xffffff00) | uint32(sqn)
}

func (counter *Count) GetOverflow() uint16 {
	return uint16((counter.Count & 0x00ffff00) >> 8)
}

func (counter *Count) SetOverflow(overflow uint16) {
	counter.Count = (counter.Count & 0xff0000ff) | (uint32(overflow) << 8)
}
