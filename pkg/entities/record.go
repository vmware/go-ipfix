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

//go:generate mockgen -copyright_file ../../license_templates/license_header.raw.txt -destination=testing/mock_record.go -package=testing github.com/vmware/go-ipfix/pkg/entities Record

// This package contains encoding of fields in the record.
// Build the record here with local buffer and write to message buffer afterwards
// Instead should we write the field directly on to message instead of having a local buffer?
// To begin with, we will have local buffer in record.
// Have an interface and expose functions to user.

type Record interface {
	PrepareRecord() (uint16, error)
	AddInfoElement(element *InfoElementWithValue, isDecoding bool) (uint16, error)
	// TODO: Functions for multiple elements as well.
	GetBuffer() *bytes.Buffer
	GetTemplateID() uint16
	GetFieldCount() uint16
	GetOrderedElementList() []*InfoElementWithValue
	GetInfoElementMap() map[string]*InfoElementWithValue
	GetMinDataRecordLen() uint16
}

type baseRecord struct {
	buff               bytes.Buffer
	len                uint16
	fieldCount         uint16
	templateID         uint16
	orderedElementList []*InfoElementWithValue
	elementsMap        map[string]*InfoElementWithValue
	Record
}

type dataRecord struct {
	*baseRecord
}

func NewDataRecord(id uint16) *dataRecord {
	return &dataRecord{
		&baseRecord{
			buff:               bytes.Buffer{},
			len:                0,
			fieldCount:         0,
			templateID:         id,
			orderedElementList: make([]*InfoElementWithValue, 0),
			elementsMap:        make(map[string]*InfoElementWithValue),
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
			buff:               bytes.Buffer{},
			len:                0,
			fieldCount:         count,
			templateID:         id,
			orderedElementList: make([]*InfoElementWithValue, 0),
			elementsMap:        make(map[string]*InfoElementWithValue),
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

func (d *baseRecord) GetOrderedElementList() []*InfoElementWithValue {
	return d.orderedElementList
}

func (d *baseRecord) GetInfoElementMap() map[string]*InfoElementWithValue {
	return d.elementsMap
}

func (d *dataRecord) PrepareRecord() (uint16, error) {
	// We do not have to do anything if it is data record
	return 0, nil
}

func (d *dataRecord) AddInfoElement(element *InfoElementWithValue, isDecoding bool) (uint16, error) {
	d.fieldCount++
	initialLength := d.buff.Len()
	var value interface{}
	var err error
	if isDecoding {
		value, err = DecodeToIEDataType(element.Element.DataType, element.Value)
	} else {
		value, err = EncodeToIEDataType(element.Element.DataType, element.Value, &d.buff)
	}

	if err != nil {
		return 0, err
	}
	ie := NewInfoElementWithValue(element.Element, value)
	d.orderedElementList = append(d.orderedElementList, ie)
	d.elementsMap[element.Element.Name] = ie
	if err != nil {
		return 0, err
	}
	return uint16(d.buff.Len() - initialLength), nil
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

func (t *templateRecord) AddInfoElement(element *InfoElementWithValue, isDecoding bool) (uint16, error) {
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
	t.orderedElementList = append(t.orderedElementList, element)
	t.elementsMap[element.Element.Name] = element
	// Keep track of minimum data record length required for sanity check
	if element.Element.Len == VariableLength {
		t.minDataRecLength = t.minDataRecLength + 1
	} else {
		t.minDataRecLength = t.minDataRecLength + element.Element.Len
	}
	return uint16(t.buff.Len() - initialLength), nil
}

func (t *templateRecord) GetMinDataRecordLen() uint16 {
	return t.minDataRecLength
}
