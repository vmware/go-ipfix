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

type TemplateSet struct {
	records []*templateRecord
}

type DataSet struct {
	records []*dataRecord
}

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

func NewTemplateSet() *TemplateSet {
	return &TemplateSet{
		records: make([]*templateRecord, 0),
	}
}

func NewDataSet() *DataSet {
	return &DataSet{
		records: make([]*dataRecord, 0),
	}
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

func (d *DataSet) AddRecord(elements []*InfoElementValue, templateID uint16, isDecoding bool) {
	record := NewDataRecord(templateID)
	for _, ieValue := range elements {
		record.AddInfoElement(ieValue.Element, ieValue.Value, isDecoding)
	}
	d.records = append(d.records, record)
}

func (d *DataSet) GetRecords() []Record {
	var recs []Record
	for _, rec := range d.records {
		recs = append(recs, rec)
	}
	return recs
}

func (t *TemplateSet) AddRecord(elements []*InfoElement, templateID uint16, isDecoding bool) {
	record := NewTemplateRecord(uint16(len(elements)), templateID)
	for _, element := range elements {
		record.AddInfoElement(element, nil, isDecoding)
	}
	t.records = append(t.records, record)
}

func (t *TemplateSet) GetRecords() []Record {
	var recs []Record
	for _, rec := range t.records {
		recs = append(recs, rec)
	}
	return recs
}
