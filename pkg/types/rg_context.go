package types

type RGType string

const (
	RGType_FN_RG    RGType = "FN_RG"
	RGType_FIVEG_RG RGType = "5G_RG"

	LineType_DSL string = "DSL"
	LineType_PON string = "PON"
)

type RGContext struct {
	RGType           RGType
	MAC              string
	LineType         string
	LineID           string
	CircuitID        string
	RemoteID         string
	UpBindAddr       string
	CreatePDUSession bool
	PDUSessionType   string
	MacUnique        bool // TS 23.316 clause 4.7.7
	WAgfInfo         WAgfInfo
}

func (ctx *RGContext) Valid() bool {
	if ctx.RGType != RGType_FN_RG && ctx.RGType != RGType_FIVEG_RG {
		return false
	}

	if ctx.LineType != LineType_PON && ctx.LineType != LineType_DSL {
		return false
	}

	if len(ctx.LineID) == 0 && len(ctx.CircuitID) == 0 && len(ctx.RemoteID) == 0 {
		return false
	}
	if (len(ctx.LineID) != 0 && len(ctx.CircuitID) != 0) || (len(ctx.LineID) != 0 && len(ctx.RemoteID) != 0) && (len(ctx.CircuitID) != 0 && len(ctx.RemoteID) != 0) {
		return false
	}

	// TR-470 Figure 18: Global Line Identifier
	if len(ctx.LineID) > 130 {
		return false
	}
	if len(ctx.LineID) != 0 {
		if ctx.LineID[0] == 0x01 {
			var components []string

			for key, value := range ctx.LineID[2:] {
				if value == 0x02 {
					components = append(components, ctx.LineID[2:key+2])
					components = append(components, ctx.LineID[key+4:])

					// Permissible values 0x01-0x3f
					if ctx.LineID[key+3] < 0x01 || ctx.LineID[key+3] > 0x3f {
						return false
					}
					// The length of Remote ID
					if len(components[1]) != int(ctx.LineID[key+3]) {
						return false
					}

					break
				}
			}

			if len(components) == 0 {
				components = append(components, ctx.LineID[2:])
			}
			// Permissible values 0x01-0x3f
			if ctx.LineID[1] < 0x01 || ctx.LineID[1] > 0x3f {
				return false
			}
			// The length of Circuit ID
			if len(components[0]) != int(ctx.LineID[1]) {
				return false
			}

			for _, component := range components {
				for _, value := range component {
					// Permissible values 0x20-0x7e
					if value < 0x20 || value > 0x7e {
						return false
					}
				}
			}
		} else if ctx.LineID[0] == 0x02 {
			// The length of Remote ID
			if ctx.LineID[1] < 0x01 || ctx.LineID[1] > 0x3f {
			}
			if len(ctx.LineID[2:]) != int(ctx.LineID[1]) {
				return false
			}

			for _, value := range ctx.LineID[2:] {
				// Permissible values 0x20-0x7e
				if value < 0x20 || value > 0x7e {
					return false
				}
			}
		} else {
			return false
		}
	}

	if len(ctx.CircuitID) > 0x3f {
		return false
	}
	for _, value := range ctx.CircuitID {
		// Permissible values 0x20-0x7e
		if value < 0x20 || value > 0x7e {
			return false
		}
	}

	if len(ctx.RemoteID) > 0x3f {
		return false
	}
	for _, value := range ctx.RemoteID {
		// Permissible values 0x20-0x7e
		if value < 0x20 || value > 0x7e {
			return false
		}
	}

	if ctx.MAC == "" {
		return false
	}

	switch ctx.PDUSessionType {
	case PDUSessionTypeIPv4:
	case PDUSessionTypeIPv6:
	case PDUSessionTypeIPv4v6:
	case PDUSessionTypeUnstructured:
	case PDUSessionTypeEthernet:
	case PDUSessionTypeReserved:
	default:
		return false
	}

	return true
}

type WAgfInfo struct {
	Ipv4EndpointAddresses []string `json:"ipv4EndpointAddresses,omitempty"`
	Ipv6EndpointAddresses []string `json:"ipv6EndpointAddresses,omitempty"`
	EndpointFqdn          string   `json:"endpointFqdn,omitempty"`
}
