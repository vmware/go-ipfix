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

	"github.com/vmware/go-ipfix/pkg/util"
)

const (
	// TemplateRefreshTimeOut is the template refresh time out for exporting process
	TemplateRefreshTimeOut uint32 = 1800
	// TemplateTTL is the template time to live for collecting process
	TemplateTTL uint32 = TemplateRefreshTimeOut * 3
	// TemplateSetID is the setID for template record
	TemplateSetID uint16 = 2
)

type ContentType uint8

const (
	Template ContentType = iota
	Data
	// Add OptionsTemplate too when it is supported
	Undefined = 255
)

// Do not expose set to IPFIX library user
// Not creating any interface. Plan to use same struct for Template and Data sets

type Set struct {
	// Pointer to message buffer
	buffer  *bytes.Buffer
	currLen uint16
	setType ContentType
}

// enterpriseID -> elementID
type TemplateSet map[uint32][]uint16

// enterpriseID -> elementID -> val
type DataSet map[uint32]map[uint16]interface{}

func NewSet(buffer *bytes.Buffer) *Set {
	return &Set{
		buffer:  buffer,
		currLen: 0,
		setType: Undefined,
	}
}

func (s *Set) CreateNewSet(setType ContentType, templateID uint16) error {
	// Create the set header and append it
	header := make([]byte, 4)
	if setType == Template {
		binary.BigEndian.PutUint16(header[0:2], TemplateSetID)
	} else if setType == Data {
		// Supporting only one templateID per exporting process
		// TODO: Add support to multiple template IDs
		binary.BigEndian.PutUint16(header[0:2], templateID)
	}
	// Write the set header to msg buffer
	_, err := s.buffer.Write(header)
	if err != nil {
		return fmt.Errorf("error when writing header to message buffer: %v", err)
	}
	// set the setType and update set length
	s.setType = setType
	s.currLen = s.currLen + uint16(len(header))

	return nil
}

func NewTemplateSet() TemplateSet {
	return make(map[uint32][]uint16)

}

func NewDataSet() DataSet {
	return make(map[uint32]map[uint16]interface{})
}

func (s *Set) GetBuffLen() uint16 {
	return s.currLen
}

func (s *Set) GetSetType() ContentType {
	return s.setType
}

func (s *Set) WriteRecordToSet(recBuffer *[]byte) error {
	_, err := s.buffer.Write(*recBuffer)
	if err != nil {
		return fmt.Errorf("error in writing the buffer to set: %v", err)
	}
	// Update the length of set
	s.currLen = s.currLen + uint16(len(*recBuffer))
	return nil
}

func (s *Set) FinishSet() {
	// TODO:Add padding when multiple sets are sent in single IPFIX message
	// Add length to the message
	byteSlice := s.buffer.Bytes()
	setOffset := s.buffer.Len() - int(s.currLen)
	binary.BigEndian.PutUint16(byteSlice[setOffset+2:setOffset+4], s.currLen)
	// Reset the length
	s.currLen = 0
}

func (d DataSet) AddInfoElement(element *InfoElement, val *bytes.Buffer) error {
	if _, exist := d[element.EnterpriseId]; !exist {
		d[element.EnterpriseId] = make(map[uint16]interface{})
	}
	switch dataType := element.DataType; dataType {
	case Unsigned8:
		var v uint8
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to uint8: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Unsigned16:
		var v uint16
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to uint16: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Unsigned32:
		var v uint32
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to uint32: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Unsigned64:
		var v uint64
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to uint64: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Signed8:
		var v int8
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to int8: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Signed16:
		var v int16
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to int16: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Signed32:
		var v int32
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to int32: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Signed64:
		var v int64
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to int64: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Float32:
		var v float32
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to float32: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Float64:
		var v float64
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to float64: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case Boolean:
		var v int
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to boolean: %v", err)
		}
		if v == 1 {
			d[element.EnterpriseId][element.ElementId] = true
		} else {
			d[element.EnterpriseId][element.ElementId] = false
		}
	case DateTimeSeconds, DateTimeMilliseconds:
		var v uint64
		err := util.Decode(val, &v)
		if err != nil {
			return fmt.Errorf("Error in decoding val to uint64: %v", err)
		}
		d[element.EnterpriseId][element.ElementId] = v
	case DateTimeMicroseconds, DateTimeNanoseconds:
		return fmt.Errorf("This API does not support micro and nano seconds types yet")
	case MacAddress, Ipv4Address, Ipv6Address:
		d[element.EnterpriseId][element.ElementId] = val.Bytes()
	case String:
		d[element.EnterpriseId][element.ElementId] = val.String()
	default:
		return fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
	}
	return nil
}

func (t TemplateSet) AddInfoElement(enterpriseID uint32, elementID uint16) {
	if _, exist := t[enterpriseID]; !exist {
		t[enterpriseID] = make([]uint16, 0)
	}
	t[enterpriseID] = append(t[enterpriseID], elementID)
}
