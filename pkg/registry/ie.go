package registry

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
	Name string
	// Identifier for IE; follows Section 4.3 of RFC7013
	ElementId uint16
	// dataType follows the specification in RFC7012(section 3.1)/RFC5610(section 3.1)
	DataType IEDataType
	// Enterprise number or 0 (0 for IANA registry)
	EnterpriseId uint32
	// Length of IE
	Len uint16
	// Add description and dataType semantics if required
}

func NewInfoElement(name string, ieID uint16, ieType IEDataType, entID uint32, len uint16) *InfoElement {
	return &InfoElement{
		Name:         name,
		ElementId:    ieID,
		DataType:     ieType,
		EnterpriseId: entID,
		Len:          len,
	}
}
