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
	AddInfoElement(element *InfoElementWithValue) error
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
	fieldCount         uint16
	templateID         uint16
	orderedElementList []*InfoElementWithValue
	isDecoding         bool
	Record
}

type dataRecord struct {
	baseRecord
}

func NewDataRecord(id uint16, numElements int, isDecoding bool) *dataRecord {
	record := &dataRecord{
		baseRecord{
			buffer:     make([]byte, 0),
			fieldCount: 0,
			templateID: id,
			isDecoding: isDecoding,
		},
	}
	if isDecoding {
		record.orderedElementList = make([]*InfoElementWithValue, numElements)
	}
	return record
}

type templateRecord struct {
	baseRecord
	// Minimum data record length required to be sent for this template.
	// Elements with variable length are considered to be one byte.
	minDataRecLength uint16
	// index is used when adding elements to orderedElementList
	index int
}

func NewTemplateRecord(id uint16, numElements int, isDecoding bool) *templateRecord {
	record := &templateRecord{
		baseRecord{
			buffer:     make([]byte, 0),
			fieldCount: uint16(numElements),
			templateID: id,
			isDecoding: isDecoding,
		},
		0,
		0,
	}
	record.orderedElementList = make([]*InfoElementWithValue, numElements)
	return record
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

func (b *baseRecord) GetOrderedElementList() []*InfoElementWithValue {
	return b.orderedElementList
}

func (b *baseRecord) GetInfoElementWithValue(name string) (*InfoElementWithValue, bool) {
	for _, element := range b.orderedElementList {
		if element.Element.Name == name {
			return element, true
		}
	}
	return nil, false
}

func (d *dataRecord) PrepareRecord() error {
	// We do not have to do anything if it is data record
	return nil
}

func (d *dataRecord) AddInfoElement(element *InfoElementWithValue) error {
	var value interface{}
	var err error
	if d.isDecoding {
		value, err = DecodeToIEDataType(element.Element.DataType, element.Value)
		if err != nil {
			return err
		}
		element.Value = value
		if len(d.orderedElementList) <= int(d.fieldCount) {
			d.orderedElementList = append(d.orderedElementList, element)
		} else {
			d.orderedElementList[d.fieldCount] = element
		}
	} else {
		buffBytes, err := EncodeToIEDataType(element.Element.DataType, element.Value)
		if err != nil {
			return err
		}
		d.buffer = append(d.buffer, buffBytes...)
	}
	d.fieldCount++
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

func (t *templateRecord) AddInfoElement(element *InfoElementWithValue) error {
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
	t.orderedElementList[t.index] = element
	t.index++
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
