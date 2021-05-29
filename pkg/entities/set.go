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
	PrepareSet(setType ContentType, templateID uint16) error
	ResetSet()
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

func NewSet(isDecoding bool) Set {
	return &set{
		buffer:     &bytes.Buffer{},
		records:    make([]Record, 0),
		isDecoding: isDecoding,
	}
}

func (s *set) PrepareSet(setType ContentType, templateID uint16) error {
	if setType == Undefined {
		return fmt.Errorf("set type is not properly defined")
	} else {
		s.setType = setType
	}
	if !s.isDecoding {
		// Create the set header and append it when encoding
		return s.createHeader(s.setType, templateID)
	}
	return nil
}

func (s *set) ResetSet() {
	s.buffer.Reset()
	s.setType = Undefined
	s.records = nil
	s.records = make([]Record, 0)
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
		record = NewDataRecord(templateID, len(elements))
	} else if s.setType == Template {
		record = NewTemplateRecord(templateID, len(elements))
		err := record.PrepareRecord()
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("set type is not supported")
	}

	for _, element := range elements {
		err := record.AddInfoElement(element, s.isDecoding)
		if err != nil {
			return err
		}
	}
	s.records = append(s.records, record)
	// write record to set when encoding
	if !s.isDecoding {
		recordBytes := record.GetBuffer()
		bytesWritten, err := s.buffer.Write(recordBytes)
		if err != nil {
			return fmt.Errorf("error in writing the buffer to set: %v", err)
		}
		if bytesWritten != len(recordBytes) {
			return fmt.Errorf("bytes written length is not expected")
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

func (s *set) createHeader(setType ContentType, templateID uint16) error {
	header := make([]byte, 4)
	if setType == Template {
		binary.BigEndian.PutUint16(header[0:2], TemplateSetID)
	} else if setType == Data {
		binary.BigEndian.PutUint16(header[0:2], templateID)
	}
	if _, err := s.buffer.Write(header); err != nil {
		return err
	}
	return nil
}
