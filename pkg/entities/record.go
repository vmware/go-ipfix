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
	"math/big"
	"net"

	"github.com/vmware/go-ipfix/pkg/util"
)

//go:generate mockgen -copyright_file ../../license_templates/license_header.raw.txt -destination=testing/mock_record.go -package=testing github.com/vmware/go-ipfix/pkg/entities Record

// This package contains encoding of fields in the record.
// Build the record here with local buffer and write to message buffer afterwards
// Instead should we write the field directly on to message instead of having a local buffer?
// To begin with, we will have local buffer in record.
// Have an interface and expose functions to user.

type Record interface {
	PrepareRecord() (uint16, error)
	AddInfoElement(element *InfoElementValue, isDecoding bool) (uint16, error)
	// TODO: Functions for multiple elements as well.
	GetBuffer() *bytes.Buffer
	GetTemplateID() uint16
	GetFieldCount() uint16
	GetInfoElements() []*InfoElementValue
	GetMinDataRecordLen() uint16
}

type baseRecord struct {
	buff       bytes.Buffer
	len        uint16
	fieldCount uint16
	templateID uint16
	elements   []*InfoElementValue
	Record
}

type dataRecord struct {
	*baseRecord
}

func NewDataRecord(id uint16) *dataRecord {
	return &dataRecord{
		&baseRecord{
			buff:       bytes.Buffer{},
			len:        0,
			fieldCount: 0,
			templateID: id,
			elements:   make([]*InfoElementValue, 0),
		},
	}
}

type templateRecord struct {
	*baseRecord
	// Minimum data record length required to be sent for this template.
	// Elements with variable length are considered to be one byte.
	minDataRecLength uint16
}

func NewTemplateRecord(count uint16, id uint16) *templateRecord {
	return &templateRecord{
		&baseRecord{
			buff:       bytes.Buffer{},
			len:        0,
			fieldCount: count,
			templateID: id,
			elements:   make([]*InfoElementValue, 0),
		},
		0,
	}
}

func (b *baseRecord) GetBuffer() *bytes.Buffer {
	return &b.buff
}

func (b *baseRecord) GetTemplateID() uint16 {
	return b.templateID
}

func (b *baseRecord) GetFieldCount() uint16 {
	return b.fieldCount
}

func (d *dataRecord) PrepareRecord() (uint16, error) {
	// We do not have to do anything if it is data record
	return 0, nil
}

func (d *dataRecord) AddInfoElement(element *InfoElementValue, isDecoding bool) (uint16, error) {
	d.fieldCount++
	initialLength := d.buff.Len()
	var value interface{}
	var err error
	if isDecoding {
		value, err = d.decodeToIEDataType(element.Element.DataType, element.Value)
	} else {
		value, err = d.encodeToIEDataType(element.Element.DataType, element.Value)
	}

	if err != nil {
		return 0, err
	}
	ie := NewInfoElementValue(element.Element, value)
	d.elements = append(d.elements, ie)
	if err != nil {
		return 0, err
	}
	return uint16(d.buff.Len() - initialLength), nil
}

func (d *dataRecord) GetInfoElements() []*InfoElementValue {
	return d.elements
}

func (t *templateRecord) PrepareRecord() (uint16, error) {
	// Add Template Record Header
	initialLength := t.buff.Len()
	err := util.Encode(&t.buff, binary.BigEndian, t.templateID, t.fieldCount)
	if err != nil {
		return 0, fmt.Errorf("AddInfoElement(templateRecord) error in writing template header: %v", err)
	}
	return uint16(t.buff.Len() - initialLength), nil
}

func (t *templateRecord) AddInfoElement(element *InfoElementValue, isDecoding bool) (uint16, error) {
	// val could be used to specify smaller length than default? For now assert it to be nil
	if element.Value != nil {
		return 0, fmt.Errorf("AddInfoElement(templateRecord) cannot take value %v (nil is expected)", element.Value)
	}
	initialLength := t.buff.Len()
	// Add field specifier {elementID: uint16, elementLen: uint16}
	err := util.Encode(&t.buff, binary.BigEndian, element.Element.ElementId, element.Element.Len)
	if err != nil {
		return 0, err
	}
	if element.Element.EnterpriseId != 0 {
		// Set the MSB of elementID to 1 as per RFC7011
		t.buff.Bytes()[initialLength] = t.buff.Bytes()[initialLength] | 0x80
		err = util.Encode(&t.buff, binary.BigEndian, element.Element.EnterpriseId)
		if err != nil {
			return 0, err
		}
	}
	t.elements = append(t.elements, element)
	// Keep track of minimum data record length required for sanity check
	if element.Element.Len == VariableLength {
		t.minDataRecLength = t.minDataRecLength + 1
	} else {
		t.minDataRecLength = t.minDataRecLength + element.Element.Len
	}
	return uint16(t.buff.Len() - initialLength), nil
}

func (t *templateRecord) GetInfoElements() []*InfoElementValue {
	return t.elements
}

func (t *templateRecord) GetMinDataRecordLen() uint16 {
	return t.minDataRecLength
}

// decodeToIEDataType is to decode to specific type
func (d *dataRecord) decodeToIEDataType(dataType IEDataType, val interface{}) (interface{}, error) {
	switch value := val.(type) {
	case *bytes.Buffer:
		{
			switch dataType {
			case Unsigned8:
				var v uint8
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to uint8: %v", err)
				}
				return v, nil
			case Unsigned16:
				var v uint16
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to uint16: %v", err)
				}
				return v, nil
			case Unsigned32:
				var v uint32
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to uint32: %v", err)
				}
				return v, nil
			case Unsigned64:
				var v uint64
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to uint64: %v", err)
				}
				return v, nil
			case Signed8:
				var v int8
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to int8: %v", err)
				}
				return v, nil
			case Signed16:
				var v int16
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to int16: %v", err)
				}
				return v, nil
			case Signed32:
				var v int32
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to int32: %v", err)
				}
				return v, nil
			case Signed64:
				var v int64
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to int64: %v", err)
				}
				return v, nil
			case Float32:
				var v float32
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to float32: %v", err)
				}
				return v, nil
			case Float64:
				var v float64
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to float64: %v", err)
				}
				return v, nil
			case Boolean:
				var v int
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to boolean: %v", err)
				}
				if v == 1 {
					return true, nil
				} else {
					return false, nil
				}
			case DateTimeSeconds, DateTimeMilliseconds:
				var v uint64
				err := util.Decode(value, binary.BigEndian, &v)
				if err != nil {
					return nil, fmt.Errorf("Error in decoding val to uint64: %v", err)
				}
				return v, nil
			case DateTimeMicroseconds, DateTimeNanoseconds:
				return nil, fmt.Errorf("This API does not support micro and nano seconds types yet")
			case MacAddress, Ipv4Address, Ipv6Address:
				return value.Bytes(), nil
			case String:
				return value.String(), nil
			default:
				return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
			}
		}
	}
	return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
}

// encodeToIEDataType is to encode to specific type to the buff
func (d *dataRecord) encodeToIEDataType(dataType IEDataType, val interface{}) (interface{}, error) {
	switch dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint8")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint16")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint32")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type uint64")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int8")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int16")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int32")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int64")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type float32")
		}
		err := util.Encode(&d.buff, binary.BigEndian, math.Float32bits(v))
		return math.Float32bits(v), err
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type float64")
		}
		err := util.Encode(&d.buff, binary.BigEndian, math.Float64bits(v))
		return math.Float64bits(v), err
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type bool")
		}
		// Following boolean spec from RFC7011
		if v {
			err := util.Encode(&d.buff, binary.BigEndian, int8(1))
			return int8(1), err
		} else {
			err := util.Encode(&d.buff, binary.BigEndian, int8(2))
			return int8(2), err
		}
	case DateTimeSeconds, DateTimeMilliseconds:
		// We expect time to be given in int64 as unix time type in go
		v, ok := val.(int64)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type int64")
		}
		err := util.Encode(&d.buff, binary.BigEndian, uint64(v))
		return uint64(v), err
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return 0, fmt.Errorf("This API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return nil, fmt.Errorf("val argument is not of type net.HardwareAddr for this element")
		}
		err := util.Encode(&d.buff, binary.BigEndian, v)
		return v, err
	case Ipv4Address, Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type net.IP for this element")
		}
		if ipv4Add := v.To4(); ipv4Add != nil {
			ipv4Int := big.NewInt(0)
			ipv4Int.SetBytes(ipv4Add)
			err := util.Encode(&d.buff, binary.BigEndian, uint32(ipv4Int.Uint64()))
			return uint32(ipv4Int.Uint64()), err
		} else {
			return v, nil
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type string for this element")
		}
		if len(v) < 255 {
			err := util.Encode(&d.buff, binary.BigEndian, uint8(len(v)), []byte(v))
			return []byte(v), err
		} else if len(v) < 65535 {
			err := util.Encode(&d.buff, binary.BigEndian, byte(255), uint16(len(v)), []byte(v))
			return []byte(v), err
		}
	default:
		return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
	return nil, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
}
