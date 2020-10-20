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
	GetBuffLen() uint16
	GetBuffer() *bytes.Buffer
	GetSetType() ContentType
	FinishSet()
	AddRecord(elements []*InfoElementWithValue, templateID uint16) error
	GetRecords() []Record
	GetNumberOfRecords() uint32
}

type set struct {
	// Pointer to message buffer
	buffer     *bytes.Buffer
	currLen    uint16
	setType    ContentType
	records    []Record
	isDecoding bool
}

func NewSet(setType ContentType, templateID uint16, isDecoding bool) Set {
	buffer := &bytes.Buffer{}
	if !isDecoding { // Create the set header and append it when encoding
		header := make([]byte, 4)
		if setType == Template {
			binary.BigEndian.PutUint16(header[0:2], TemplateSetID)
		} else if setType == Data {
			// Supporting only one templateID per exporting process
			// TODO: Add support to multiple template IDs
			binary.BigEndian.PutUint16(header[0:2], templateID)
		}
		// Write the set header to msg buffer
		buffer.Write(header)
	}
	return &set{
		buffer:     buffer,
		currLen:    uint16(buffer.Len()),
		setType:    setType,
		records:    make([]Record, 0),
		isDecoding: isDecoding,
	}
}

func (s *set) GetBuffLen() uint16 {
	return s.currLen
}

func (s *set) GetBuffer() *bytes.Buffer {
	return s.buffer
}

func (s *set) GetSetType() ContentType {
	return s.setType
}

func (s *set) FinishSet() {
	// TODO:Add padding when multiple sets are sent in single IPFIX message
	// Add length to the message
	byteSlice := s.buffer.Bytes()
	setOffset := s.buffer.Len() - int(s.currLen)
	binary.BigEndian.PutUint16(byteSlice[setOffset+2:setOffset+4], s.currLen)
	// Reset the length
	s.currLen = 0
}

func (s *set) AddRecord(elements []*InfoElementWithValue, templateID uint16) error {
	var record Record
	if s.setType == Data {
		record = NewDataRecord(templateID)
	} else if s.setType == Template {
		record = NewTemplateRecord(uint16(len(elements)), templateID)
	}
	record.PrepareRecord()
	for _, element := range elements {
		record.AddInfoElement(element, s.isDecoding)
	}
	s.records = append(s.records, record)
	// write record to set when encoding
	if !s.isDecoding {
		recordBytes := record.GetBuffer().Bytes()
		_, err := s.buffer.Write(recordBytes)
		if err != nil {
			return fmt.Errorf("error in writing the buffer to set: %v", err)
		}
		// Update the length of set
		s.currLen = s.currLen + uint16(len(recordBytes))
	}
	return nil
}

func (s *set) GetRecords() []Record {
	return s.records
}

func (s *set) GetNumberOfRecords() uint32 {
	return uint32(len(s.records))
}
