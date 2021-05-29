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
)

//go:generate mockgen -copyright_file ../../license_templates/license_header.raw.txt -destination=testing/mock_record.go -package=testing github.com/vmware/go-ipfix/pkg/entities Record

// This package contains encoding of fields in the record.
// Build the record here with local buffer and write to message buffer afterwards
// Instead should we write the field directly on to message instead of having a local buffer?
// To begin with, we will have local buffer in record.
// Have an interface and expose functions to user.

type Record interface {
	PrepareRecord() error
	AddInfoElement(element *InfoElementWithValue, isDecoding bool) error
	// TODO: Functions for multiple elements as well.
	GetBuffer() []byte
	GetTemplateID() uint16
	GetFieldCount() uint16
	GetOrderedElementList() []*InfoElementWithValue
	GetInfoElementWithValue(name string) (*InfoElementWithValue, bool)
	GetMinDataRecordLen() uint16
}

type baseRecord struct {
	buffer             []byte
	len                int
	fieldCount         uint16
	templateID         uint16
	orderedElementList []*InfoElementWithValue
	elementsMap        map[string]*InfoElementWithValue
	Record
}

type dataRecord struct {
	baseRecord
}

func NewDataRecord(id uint16, numElements int) *dataRecord {
	return &dataRecord{
		baseRecord{
			buffer:             make([]byte, 0),
			len:                0,
			fieldCount:         0,
			templateID:         id,
			orderedElementList: make([]*InfoElementWithValue, 0),
			elementsMap:        make(map[string]*InfoElementWithValue, numElements),
		},
	}
}

type templateRecord struct {
	baseRecord
	// Minimum data record length required to be sent for this template.
	// Elements with variable length are considered to be one byte.
	minDataRecLength uint16
}

func NewTemplateRecord(id uint16, numElements int) *templateRecord {
	return &templateRecord{
		baseRecord{
			buffer:             make([]byte, 0),
			len:                0,
			fieldCount:         uint16(numElements),
			templateID:         id,
			orderedElementList: make([]*InfoElementWithValue, 0),
			elementsMap:        make(map[string]*InfoElementWithValue, numElements),
		},
		0,
	}
}

func (b *baseRecord) GetBuffer() []byte {
	return b.buffer
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

func (b *baseRecord) GetInfoElementWithValue(name string) (*InfoElementWithValue, bool) {
	if element, exist := b.elementsMap[name]; exist {
		return element, exist
	} else {
		return nil, false
	}
}

func (d *dataRecord) PrepareRecord() error {
	// We do not have to do anything if it is data record
	return nil
}

func (d *dataRecord) AddInfoElement(element *InfoElementWithValue, isDecoding bool) error {
	d.fieldCount++
	var value interface{}
	var err error
	if isDecoding {
		value, err = DecodeToIEDataType(element.Element.DataType, element.Value)
		if err != nil {
			return err
		}
		element.Value = value
	} else {
		buffBytes, err := EncodeToIEDataType(element.Element.DataType, element.Value)
		if err != nil {
			return err
		}
		d.buffer = append(d.buffer, buffBytes...)
	}

	d.orderedElementList = append(d.orderedElementList, element)
	d.elementsMap[element.Element.Name] = element
	return nil
}

func (t *templateRecord) PrepareRecord() error {
	// Add Template Record Header
	addBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(addBytes, t.templateID)
	t.buffer = append(t.buffer, addBytes...)
	addBytes = make([]byte, 2)
	binary.BigEndian.PutUint16(addBytes, t.fieldCount)
	t.buffer = append(t.buffer, addBytes...)
	return nil
}

func (t *templateRecord) AddInfoElement(element *InfoElementWithValue, isDecoding bool) error {
	// val could be used to specify smaller length than default? For now assert it to be nil
	if element.Value != nil {
		return fmt.Errorf("AddInfoElement(templateRecord) cannot take value %v (nil is expected)", element.Value)
	}
	initialLength := len(t.buffer)
	// Add field specifier {elementID: uint16, elementLen: uint16}
	addBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(addBytes, element.Element.ElementId)
	t.buffer = append(t.buffer, addBytes...)
	addBytes = make([]byte, 2)
	binary.BigEndian.PutUint16(addBytes, element.Element.Len)
	t.buffer = append(t.buffer, addBytes...)
	if element.Element.EnterpriseId != 0 {
		// Set the MSB of elementID to 1 as per RFC7011
		t.buffer[initialLength] = t.buffer[initialLength] | 0x80
		addBytes = make([]byte, 4)
		binary.BigEndian.PutUint32(addBytes, element.Element.EnterpriseId)
		t.buffer = append(t.buffer, addBytes...)
	}
	t.orderedElementList = append(t.orderedElementList, element)
	t.elementsMap[element.Element.Name] = element
	// Keep track of minimum data record length required for sanity check
	if element.Element.Len == VariableLength {
		t.minDataRecLength = t.minDataRecLength + 1
	} else {
		t.minDataRecLength = t.minDataRecLength + element.Element.Len
	}
	return nil
}

func (t *templateRecord) GetMinDataRecordLen() uint16 {
	return t.minDataRecLength
}
