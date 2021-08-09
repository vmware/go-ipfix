// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entities

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

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

var InfoElementLength = map[IEDataType]uint16{
	OctetArray:           VariableLength,
	Unsigned8:            1,
	Unsigned16:           2,
	Unsigned32:           4,
	Unsigned64:           8,
	Signed8:              1,
	Signed16:             2,
	Signed32:             4,
	Signed64:             8,
	Float32:              4,
	Float64:              8,
	Boolean:              1,
	MacAddress:           6,
	String:               VariableLength,
	DateTimeSeconds:      4,
	DateTimeMilliseconds: 8,
	DateTimeMicroseconds: 8,
	DateTimeNanoseconds:  8,
	Ipv4Address:          4,
	Ipv6Address:          16,
	BasicList:            VariableLength,
	SubTemplateList:      VariableLength,
	SubTemplateMultiList: VariableLength,
	InvalidDataType:      0,
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
}

// InfoElementWithValue represents mapping from element to value for data records
type InfoElementWithValue struct {
	Element *InfoElement
	Value   interface{}
	Length  int
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

func NewInfoElementWithValue(element *InfoElement, value interface{}) InfoElementWithValue {
	return InfoElementWithValue{
		element, value, 0,
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

// DecodeToIEDataType is to decode to specific type
func DecodeToIEDataType(dataType IEDataType, val interface{}) (interface{}, error) {
	value, ok := val.([]byte)
	if !ok {
		return nil, fmt.Errorf("error when converting value to []bytes for decoding")
	}
	switch dataType {
	case Unsigned8:
		return value[0], nil
	case Unsigned16:
		return binary.BigEndian.Uint16(value), nil
	case Unsigned32:
		return binary.BigEndian.Uint32(value), nil
	case Unsigned64:
		return binary.BigEndian.Uint64(value), nil
	case Signed8:
		return int8(value[0]), nil
	case Signed16:
		return int16(binary.BigEndian.Uint16(value)), nil
	case Signed32:
		return int32(binary.BigEndian.Uint32(value)), nil
	case Signed64:
		return int64(binary.BigEndian.Uint64(value)), nil
	case Float32:
		return math.Float32frombits(binary.BigEndian.Uint32(value)), nil
	case Float64:
		return math.Float64frombits(binary.BigEndian.Uint64(value)), nil
	case Boolean:
		if int8(value[0]) == 1 {
			return true, nil
		} else {
			return false, nil
		}
	case DateTimeSeconds:
		v := binary.BigEndian.Uint32(value)
		return v, nil
	case DateTimeMilliseconds:
		v := binary.BigEndian.Uint64(value)
		return v, nil
	case DateTimeMicroseconds, DateTimeNanoseconds:
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		return net.HardwareAddr(value), nil
	case Ipv4Address, Ipv6Address:
		return net.IP(value), nil
	case String:
		return string(value), nil
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
}

// EncodeToIEDataType is to encode data to specific type to the buff
func EncodeToIEDataType(dataType IEDataType, val interface{}) ([]byte, error) {
	switch dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint8", val)
		}
		return []byte{v}, nil
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint16", val)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, v)
		return b, nil
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b, nil
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int8", val)
		}
		return []byte{byte(v)}, nil
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int16", val)
		}
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v))
		return b, nil
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b, nil
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type int64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(v))
		return b, nil
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type float32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, math.Float32bits(v))
		return b, nil
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type float64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, math.Float64bits(v))
		return b, nil
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type bool", val)
		}
		b := make([]byte, 1)
		// Following boolean spec from RFC7011
		if v {
			b[0] = byte(int8(1))
		} else {
			b[0] = byte(int8(2))
		}
		return b, nil
	case DateTimeSeconds:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint32", val)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b, nil
	case DateTimeMilliseconds:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type uint64", val)
		}
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v)
		return b, nil
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.HardwareAddr for this element", val)
		}
		return v, nil
	case Ipv4Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv4Add := v.To4(); ipv4Add != nil {
			return ipv4Add, nil
		} else {
			return nil, fmt.Errorf("provided IP %v does not belong to IPv4 address family", v)
		}
	case Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv6Add := v.To16(); ipv6Add != nil {
			return ipv6Add, nil
		} else {
			return nil, fmt.Errorf("provided IPv6 address %v is not of correct length", v)
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("val argument %v is not of type string for this element", val)
		}
		var encodedBytes []byte
		if len(v) < 255 {
			encodedBytes = make([]byte, len(v)+1)
			encodedBytes[0] = uint8(len(v))
			for i, b := range v {
				encodedBytes[i+1] = byte(b)
			}
		} else if len(v) < 65535 {
			encodedBytes = make([]byte, len(v)+3)
			encodedBytes[0] = byte(255)
			binary.BigEndian.PutUint16(encodedBytes[1:3], uint16(len(v)))
			for i, b := range v {
				encodedBytes[i+3] = byte(b)
			}
		}
		return encodedBytes, nil
	}
	return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
}

// encodeToBuff is to encode data to specific type to the buff
func encodeToBuff(dataType IEDataType, val interface{}, length int, buffer []byte, index int) error {
	if index+length > len(buffer) {
		return fmt.Errorf("buffer size is not enough for encoding")
	}
	switch dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint8", val)
		}
		copy(buffer[index:index+1], []byte{v})
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint16", val)
		}
		binary.BigEndian.PutUint16(buffer[index:], v)
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint32", val)
		}
		binary.BigEndian.PutUint32(buffer[index:], v)
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint64", val)
		}
		binary.BigEndian.PutUint64(buffer[index:], v)
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return fmt.Errorf("val argument %v is not of type int8", val)
		}
		copy(buffer[index:index+1], []byte{byte(v)})
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return fmt.Errorf("val argument %v is not of type int16", val)
		}
		binary.BigEndian.PutUint16(buffer[index:], uint16(v))
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return fmt.Errorf("val argument %v is not of type int32", val)
		}
		binary.BigEndian.PutUint32(buffer[index:], uint32(v))
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return fmt.Errorf("val argument %v is not of type int64", val)
		}
		binary.BigEndian.PutUint64(buffer[index:], uint64(v))
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return fmt.Errorf("val argument %v is not of type float32", val)
		}
		binary.BigEndian.PutUint32(buffer[index:], math.Float32bits(v))
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return fmt.Errorf("val argument %v is not of type float64", val)
		}
		binary.BigEndian.PutUint64(buffer[index:], math.Float64bits(v))
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("val argument %v is not of type bool", val)
		}
		// Following boolean spec from RFC7011
		indicator := byte(int8(1))
		if !v {
			indicator = byte(int8(2))
		}
		copy(buffer[index:index+1], []byte{indicator})
	case DateTimeSeconds:
		v, ok := val.(uint32)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint32", val)
		}
		binary.BigEndian.PutUint32(buffer[index:], v)
	case DateTimeMilliseconds:
		v, ok := val.(uint64)
		if !ok {
			return fmt.Errorf("val argument %v is not of type uint64", val)
		}
		binary.BigEndian.PutUint64(buffer[index:], v)
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return fmt.Errorf("val argument %v is not of type net.HardwareAddr for this element", val)
		}
		copy(buffer[index:], v)
	case Ipv4Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv4Add := v.To4(); ipv4Add != nil {
			copy(buffer[index:], ipv4Add)
		} else {
			return fmt.Errorf("provided IP %v does not belong to IPv4 address family", v)
		}
	case Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return fmt.Errorf("val argument %v is not of type net.IP for this element", val)
		}
		if ipv6Add := v.To16(); ipv6Add != nil {
			copy(buffer[index:], ipv6Add)
		} else {
			return fmt.Errorf("provided IPv6 address %v is not of correct length", v)
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return fmt.Errorf("val argument %v is not of type string for this element", val)
		}
		if len(v) < 255 {
			buffer[index] = uint8(len(v))
			for i, b := range v {
				buffer[i+index+1] = byte(b)
			}
		} else if len(v) < 65535 {
			buffer[index] = byte(255)
			binary.BigEndian.PutUint16(buffer[index+1:index+3], uint16(len(v)))
			for i, b := range v {
				buffer[i+index+3] = byte(b)
			}
		}
	default:
		return fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
	return nil
}

func setInfoElementLen(element *InfoElementWithValue) {
	if element.Element.DataType != String {
		element.Length = int(element.Element.Len)
	} else {
		v := element.Value.(string)
		if len(v) < 255 {
			element.Length = len(v) + 1
		} else {
			element.Length = len(v) + 3
		}
	}
}
