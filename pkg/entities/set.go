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
	TemplateTTL = TemplateRefreshTimeOut * 3
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
	UpdateLenInHeader()
	AddRecord(elements []*InfoElementWithValue, templateID uint16) error
	GetRecords() []Record
	GetNumberOfRecords() uint32
}

type set struct {
	// Pointer to message buffer
	buffer     *bytes.Buffer
	setType    ContentType
	records    []Record
	isDecoding bool
}

func NewSet(setType ContentType, templateID uint16, isDecoding bool) Set {
	set := &set{
		buffer:     &bytes.Buffer{},
		setType:    setType,
		records:    make([]Record, 0),
		isDecoding: isDecoding,
	}
	if !isDecoding {
		// Create the set header and append it when encoding
		set.createHeader(setType, templateID)
	}
	return set
}

func (s *set) GetBuffLen() uint16 {
	return uint16(s.buffer.Len())
}

func (s *set) GetBuffer() *bytes.Buffer {
	return s.buffer
}

func (s *set) GetSetType() ContentType {
	return s.setType
}

func (s *set) UpdateLenInHeader() {
	// TODO:Add padding to the length when multiple sets are sent in IPFIX message
	if !s.isDecoding {
		// Add length to the set header
		binary.BigEndian.PutUint16(s.buffer.Bytes()[2:4], uint16(s.buffer.Len()))
	}
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
	}
	return nil
}

func (s *set) GetRecords() []Record {
	return s.records
}

func (s *set) GetNumberOfRecords() uint32 {
	return uint32(len(s.records))
}

func (s *set) createHeader(setType ContentType, templateID uint16) {
	header := make([]byte, 4)
	if setType == Template {
		binary.BigEndian.PutUint16(header[0:2], TemplateSetID)
	} else if setType == Data {
		binary.BigEndian.PutUint16(header[0:2], templateID)
	}
	// TODO: Handle this error in a future PR.
	s.buffer.Write(header)
}
