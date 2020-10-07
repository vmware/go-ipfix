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
	AddInfoElement(element *InfoElement, val interface{}) (uint16, error)
	// TODO: Functions for multiple elements as well.
	GetBuffer() *bytes.Buffer
	GetTemplateID() uint16
	GetFieldCount() uint16
	GetTemplateElements() []*InfoElement
	GetMinDataRecordLen() uint16
}

// TODO: Create base record struct. Some functions like GetBuffer will be applicable to base record.
type baseRecord struct {
	buff       bytes.Buffer
	len        uint16
	fieldCount uint16
	templateID uint16
	Record
}

type dataRecord struct {
	*baseRecord
}

func NewDataRecord(id uint16) *dataRecord {
	return &dataRecord{
		&baseRecord{buff: bytes.Buffer{}, len: 0, fieldCount: 0, templateID: id},
	}
}

type templateRecord struct {
	*baseRecord
	templateElements []*InfoElement
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
		},
		make([]*InfoElement, 0),
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

func (d *dataRecord) AddInfoElement(element *InfoElement, val interface{}) (uint16, error) {
	d.fieldCount++
	initialLength := d.buff.Len()
	var err error
	switch dataType := element.DataType; dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint8")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint16")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint32")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type uint64")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type int8")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type int16")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type int32")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type int64")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type float32")
		}
		err = util.Encode(&d.buff, binary.BigEndian, math.Float32bits(v))
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type float64")
		}
		err = util.Encode(&d.buff, binary.BigEndian, math.Float64bits(v))
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type bool")
		}
		// Following boolean spec from RFC7011
		if v {
			err = util.Encode(&d.buff, binary.BigEndian, int8(1))
		} else {
			err = util.Encode(&d.buff, binary.BigEndian, int8(2))
		}
	case DateTimeSeconds, DateTimeMilliseconds:
		// We expect time to be given in int64 as unix time type in go
		v, ok := val.(int64)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type int64")
		}
		err = util.Encode(&d.buff, binary.BigEndian, uint64(v))
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return 0, fmt.Errorf("This API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type net.HardwareAddr for this element")
		}
		err = util.Encode(&d.buff, binary.BigEndian, v)
		//bytesToAppend = append(bytesToAppend, []byte(v)...)
	case Ipv4Address, Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type net.IP for this element")
		}
		if ipv4Add := v.To4(); ipv4Add != nil {
			ipv4Int := big.NewInt(0)
			ipv4Int.SetBytes(ipv4Add)
			err = util.Encode(&d.buff, binary.BigEndian, uint32(ipv4Int.Uint64()))
		} else {
			err = util.Encode(&d.buff, binary.BigEndian, v)
		}
	case String:
		v, ok := val.(string)
		if !ok {
			return 0, fmt.Errorf("val argument is not of type string for this element")
		}
		if len(v) < 255 {
			err = util.Encode(&d.buff, binary.BigEndian, uint8(len(v)), []byte(v))
		} else if len(v) < 65535 {
			err = util.Encode(&d.buff, binary.BigEndian, byte(255), uint16(len(v)), []byte(v))
		}
	default:
		return 0, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}

	if err != nil {
		return 0, err
	}

	return uint16(d.buff.Len()-initialLength), nil
}

func (t *templateRecord) PrepareRecord() (uint16, error) {
	// Add Template Record Header
	initialLength := t.buff.Len()
	err := util.Encode(&t.buff, binary.BigEndian, t.templateID, t.fieldCount)
	if err != nil {
		return 0, fmt.Errorf("AddInfoElement(templateRecord) error in writing template header: %v", err)
	}
	return uint16(t.buff.Len()-initialLength), nil
}

func (t *templateRecord) AddInfoElement(element *InfoElement, val interface{}) (uint16, error) {
	// val could be used to specify smaller length than default? For now assert it to be nil
	if val != nil {
		return 0, fmt.Errorf("AddInfoElement(templateRecord) cannot take value %v (nil is expected)", val)
	}
	initialLength := t.buff.Len()
	// Add field specifier {elementID: uint16, elementLen: uint16}
	err := util.Encode(&t.buff, binary.BigEndian, element.ElementId, element.Len)
	if err != nil {
		return 0, err
	}
	if element.EnterpriseId != 0 {
		// Set the MSB of elementID to 1 as per RFC7011
		t.buff.Bytes()[initialLength] = t.buff.Bytes()[initialLength] | 0x80
		err = util.Encode(&t.buff, binary.BigEndian, element.EnterpriseId)
		if err != nil {
			return 0, err
		}
	}
	t.templateElements = append(t.templateElements, element)
	// Keep track of minimum data record length required for sanity check
	if element.Len == VariableLength {
		t.minDataRecLength = t.minDataRecLength + 1
	} else {
		t.minDataRecLength = t.minDataRecLength + element.Len
	}
	return uint16(t.buff.Len()-initialLength), nil
}

func (t *templateRecord) GetTemplateElements() []*InfoElement {
	return t.templateElements
}

func (t *templateRecord) GetMinDataRecordLen() uint16 {
	return t.minDataRecLength
}
