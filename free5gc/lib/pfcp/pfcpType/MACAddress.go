package pfcpType

import (
	"io"
	"net"
)

const (
	SOUR = 1
	DEST = 1 << 1
	USOU = 1 << 2
	UDES = 1 << 3
)

type MACAddress struct {
	Flags                      uint8
	SourceMACAddress           net.HardwareAddr
	DestinationMACAddress      net.HardwareAddr
	UpperSourceMACAddress      net.HardwareAddr
	UpperDestinationMACAddress net.HardwareAddr
}

// HasUDES reports whether UDES flag is set.
func (f *MACAddress) HasUDES() bool {
	return (f.Flags&UDES)>>3 == 1
}

// SetUDESFlag sets UDES flag in MACAddress.
func (f *MACAddress) SetUDESFlag() {
	f.Flags |= UDES
}

// HasUSOU reports whether USOU flag is set.
func (f *MACAddress) HasUSOU() bool {
	return (f.Flags&USOU)>>2 == 1
}

// SetUSOUFlag sets USOU flag in MACAddress.
func (f *MACAddress) SetUSOUFlag() {
	f.Flags |= USOU
}

// HasDEST reports whether DEST flag is set.
func (f *MACAddress) HasDEST() bool {
	return (f.Flags&DEST)>>1 == 1
}

// SetDESTFlag sets DEST flag in MACAddress.
func (f *MACAddress) SetDESTFlag() {
	f.Flags |= DEST
}

// HasSOUR reports whether SOUR flag is set.
func (f *MACAddress) HasSOUR() bool {
	return (f.Flags & SOUR) == 1
}

// SetSOURFlag sets SOUR flag in MACAddress.
func (f *MACAddress) SetSOURFlag() {
	f.Flags |= SOUR
}

// ParseMACAddress parses b into MACAddress.
func ParseMACAddress(b []byte) (*MACAddress, error) {
	f := &MACAddress{}
	if err := f.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return f, nil
}

// UnmarshalBinary parses b into IE.
func (f *MACAddress) UnmarshalBinary(b []byte) error {
	l := len(b)
	if l < 2 {
		return io.ErrUnexpectedEOF
	}

	f.Flags = b[0]
	offset := 1

	if f.HasSOUR() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(f.SourceMACAddress, b[offset:offset+6])
		offset += 6
	}

	if f.HasDEST() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(f.DestinationMACAddress, b[offset:offset+6])
		offset += 6
	}

	if f.HasUSOU() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(f.UpperSourceMACAddress, b[offset:offset+6])
		offset += 6
	}

	if f.HasUDES() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(f.UpperDestinationMACAddress, b[offset:offset+6])
	}

	return nil
}

// Marshal returns the serialized bytes of MACAddress.
func (f *MACAddress) MarshalBinary() ([]byte, error) {
	b := make([]byte, f.MarshalLen())
	if err := f.MarshalTo(b); err != nil {
		return nil, err
	}
	return b, nil
}

// MarshalTo puts the byte sequence in the byte array given as b.
func (f *MACAddress) MarshalTo(b []byte) error {
	l := len(b)
	if l < 1 {
		return io.ErrUnexpectedEOF
	}

	b[0] = f.Flags
	offset := 1

	if f.HasSOUR() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(b[offset:offset+6], f.SourceMACAddress[:6])
		offset += 6
	}

	if f.HasDEST() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(b[offset:offset+6], f.DestinationMACAddress[:6])
		offset += 6
	}

	if f.HasUSOU() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(b[offset:offset+6], f.UpperSourceMACAddress[:6])
		offset += 6
	}

	if f.HasUDES() {
		if l < offset+6 {
			return io.ErrUnexpectedEOF
		}
		copy(b[offset:offset+6], f.UpperDestinationMACAddress[:6])
	}

	return nil
}

// MarshalLen returns field length in integer.
func (f *MACAddress) MarshalLen() int {
	l := 1
	if f.SourceMACAddress != nil {
		l += 6
	}
	if f.DestinationMACAddress != nil {
		l += 6
	}
	if f.UpperSourceMACAddress != nil {
		l += 6
	}
	if f.UpperDestinationMACAddress != nil {
		l += 6
	}
	return l
}
