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
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/vmware/go-ipfix/pkg/util"
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
	DateTimeSeconds:      8,
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

func NewInfoElementWithValue(element *InfoElement, value interface{}) *InfoElementWithValue {
	return &InfoElementWithValue{
		element, value,
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
	value, ok := val.(*bytes.Buffer)
	if !ok {
		return nil, fmt.Errorf("error when converting value to bytes.Buffer for decoding")
	}
	switch dataType {
	case Unsigned8:
		var v uint8
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to uint8: %v", err)
		}
		return v, nil
	case Unsigned16:
		var v uint16
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to uint16: %v", err)
		}
		return v, nil
	case Unsigned32:
		var v uint32
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to uint32: %v", err)
		}
		return v, nil
	case Unsigned64:
		var v uint64
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to uint64: %v", err)
		}
		return v, nil
	case Signed8:
		var v int8
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to int8: %v", err)
		}
		return v, nil
	case Signed16:
		var v int16
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to int16: %v", err)
		}
		return v, nil
	case Signed32:
		var v int32
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to int32: %v", err)
		}
		return v, nil
	case Signed64:
		var v int64
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to int64: %v", err)
		}
		return v, nil
	case Float32:
		var v float32
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to float32: %v", err)
		}
		return v, nil
	case Float64:
		var v float64
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to float64: %v", err)
		}
		return v, nil
	case Boolean:
		var v int8
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error when decoding val to boolean: %v", err)
		}
		if v == 1 {
			return true, nil
		} else {
			return false, nil
		}
	case DateTimeSeconds:
		var v uint32
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding val to uint32: %v", err)
		}
		return v, nil
	case DateTimeMilliseconds:
		var v uint64
		err := util.Decode(value, binary.BigEndian, &v)
		if err != nil {
			return nil, fmt.Errorf("error in decoding val to uint64: %v", err)
		}
		return v, nil
	case DateTimeMicroseconds, DateTimeNanoseconds:
		return nil, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		return net.HardwareAddr(value.Bytes()), nil
	case Ipv4Address, Ipv6Address:
		return net.IP(value.Bytes()), nil
	case String:
		return value.String(), nil
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
}

// EncodeToIEDataType is to encode data to specific type to the buff
func EncodeToIEDataType(dataType IEDataType, val interface{}, buff *bytes.Buffer) (interface{}, error) {
	switch dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint8")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint16")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint32")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint64")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int8")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int16")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int32")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int64")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type float32")
		}
		err := util.Encode(buff, binary.BigEndian, math.Float32bits(v))
		return math.Float32bits(v), err
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type float64")
		}
		err := util.Encode(buff, binary.BigEndian, math.Float64bits(v))
		return math.Float64bits(v), err
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type bool")
		}
		// Following boolean spec from RFC7011
		if v {
			err := util.Encode(buff, binary.BigEndian, int8(1))
			return int8(1), err
		} else {
			err := util.Encode(buff, binary.BigEndian, int8(2))
			return int8(2), err
		}
	case DateTimeSeconds:
		v, ok := val.(uint32)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint32")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case DateTimeMilliseconds:
		v, ok := val.(uint64)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint64")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return 0, fmt.Errorf("API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type net.HardwareAddr for this element")
		}
		err := util.Encode(buff, binary.BigEndian, v)
		return v, err
	case Ipv4Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type net.IP for this element")
		}
		if ipv4Add := v.To4(); ipv4Add != nil {
			err := util.Encode(buff, binary.BigEndian, ipv4Add)
			return ipv4Add, err
		} else {
			return 0, fmt.Errorf("provided IP does not belong to IPv4 address family")
		}
	case Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type net.IP for this element")
		}
		if ipv6Add := v.To16(); ipv6Add != nil {
			err := util.Encode(buff, binary.BigEndian, v)
			return v, err
		} else {
			return 0, fmt.Errorf("provided IPv6 address is not of correct length")
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type string for this element")
		}
		if len(v) < 255 {
			err := util.Encode(buff, binary.BigEndian, uint8(len(v)), []byte(v))
			return []byte(v), err
		} else if len(v) < 65535 {
			err := util.Encode(buff, binary.BigEndian, byte(255), uint16(len(v)), []byte(v))
			return []byte(v), err
		}
	}
	return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
}
