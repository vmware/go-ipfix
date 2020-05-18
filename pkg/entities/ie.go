package entities

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
	InvalidDataType = 255
)

const VariableLength uint16 = 65535

var InfoElementLength = [...]uint16 {
	VariableLength,
	1,
	2,
	4,
	8,
	1,
	2,
	4,
	8,
	4,
	8,
	1,
	6,
	VariableLength,
	4,
	8,
	8,
	8,
	4,
	16,
	VariableLength,
	VariableLength,
	VariableLength,
	0,
}

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

func IENameToType(name string) IEDataType {
	switch name {
	case "octetArray":
		return OctetArray
	case "unsigned8":
		return Unsigned8
	case "unsigned16":
		return Unsigned16
	case "unsigned32":
		return Unsigned32
	case "unsigned64":
		return Unsigned64
	case "signed8":
		return Signed8
	case "signed16":
		return Signed16
	case "signed32":
		return Signed32
	case "signed64":
		return Signed64
	case "float32":
		return Float32
	case "float64":
		return Float64
	case "boolean":
		return Boolean
	case "macAddress":
		return MacAddress
	case "string":
		return String
	case "dateTimeSeconds":
		return DateTimeSeconds
	case "dateTimeMilliseconds":
		return DateTimeMilliseconds
	case "dateTimeMicroseconds":
		return DateTimeMicroseconds
	case "dateTimeNanoseconds":
		return DateTimeNanoseconds
	case "ipv4Address":
		return Ipv4Address
	case "ipv6Address":
		return Ipv6Address
	case "basicList":
		return BasicList
	case "subTemplateList":
		return SubTemplateList
	case "subTemplateMultiList":
		return SubTemplateMultiList
	}
	return InvalidDataType
}

func IsValidDataType(tp IEDataType) bool {
	return tp != InvalidDataType
}