package infoelements

type IEDataType uint8

const (
	OctetArray IEDataType = iota
	Unsigned8
	Unsigned16
	Unsigned32
	Unsigned64
	Signed8
	Signed16
	Signed32
	Signed64
	Float32
	Float64
	Boolean
	MacAddress
	String
	DateTimeSeconds
	DateTimeMilliseconds
	DateTimeMicroseconds
	DateTimeNanoseconds
	Ipv4Address
	Ipv6Address
	BasicList
	SubTemplateList
	SubTemplateMultiList
)

// InfoElement (IE) follows the specification in Section 2.1 of RFC7012
type InfoElement struct {
	// Name of the IE
	name string
	// Identifier for IE; follows Section 4.3 of RFC7013
	elementId uint16
	// dataType follows the specification in RFC7012(section 3.1)/RFC5610(section 3.1)
	dataType IEDataType
	// Enterprise number or 0 (0 for IANA registry)
	enterpriseId uint32
	// Length of IE
	len uint16
	// Add description and dataType semantics if required
}

func NewInfoElement(name string, ieID uint16, ieType IEDataType, entID uint32, len uint16) *InfoElement {
	return &InfoElement{
		name:         name,
		elementId:    ieID,
		dataType:     ieType,
		enterpriseId: entID,
		len:          len,
	}
}
