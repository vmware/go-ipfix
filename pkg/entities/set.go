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

//go:generate mockgen -copyright_file ../../license_templates/license_header.raw.txt -destination=testing/mock_set.go -package=testing github.com/vmware/go-ipfix/pkg/entities Set

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

type Set interface {
	CreateNewSet(setType ContentType, templateID uint16) error
	GetBuffLen() uint16
	GetSetType() ContentType
	WriteRecordToSet(recBuffer *[]byte) error
	FinishSet()
	AddRecord(elements []*InfoElementValue, templateID uint16, isDecoding bool)
	GetRecords() []Record
	GetNumberOfRecords() uint32
}

type baseSet struct {
	// Pointer to message buffer
	buffer  *bytes.Buffer
	currLen uint16
	setType ContentType
	records []Record
}

func NewSet(buffer *bytes.Buffer) Set {
	return &baseSet{
		buffer:  buffer,
		currLen: 0,
		setType: Undefined,
		records: make([]Record, 0),
	}
}

func (s *baseSet) CreateNewSet(setType ContentType, templateID uint16) error {
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

func (s *baseSet) GetBuffLen() uint16 {
	return s.currLen
}

func (s *baseSet) GetSetType() ContentType {
	return s.setType
}

func (s *baseSet) WriteRecordToSet(recBuffer *[]byte) error {
	_, err := s.buffer.Write(*recBuffer)
	if err != nil {
		return fmt.Errorf("error in writing the buffer to set: %v", err)
	}
	// Update the length of set
	s.currLen = s.currLen + uint16(len(*recBuffer))
	return nil
}

func (s *baseSet) FinishSet() {
	// TODO:Add padding when multiple sets are sent in single IPFIX message
	// Add length to the message
	byteSlice := s.buffer.Bytes()
	setOffset := s.buffer.Len() - int(s.currLen)
	binary.BigEndian.PutUint16(byteSlice[setOffset+2:setOffset+4], s.currLen)
	// Reset the length
	s.currLen = 0
}

func (b *baseSet) AddRecord(elements []*InfoElementValue, templateID uint16, isDecoding bool) {
	var record Record
	if b.setType == Data {
		record = NewDataRecord(templateID)
	} else if b.setType == Template {
		record = NewTemplateRecord(uint16(len(elements)), templateID)
	}
	record.PrepareRecord()
	for _, element := range elements {
		record.AddInfoElement(element, isDecoding)
	}
	b.records = append(b.records, record)
}

func (b *baseSet) GetRecords() []Record {
	return b.records
}

func (b *baseSet) GetNumberOfRecords() uint32 {
	return uint32(len(b.records))
}
