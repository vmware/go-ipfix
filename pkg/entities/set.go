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

	"github.com/vmware/go-ipfix/pkg/config"
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

type templateSet struct {
	// enterpriseID -> elementID
	elements map[uint32][]uint16
}

type dataSet struct {
	// enterpriseID -> elementID -> val
	elements map[uint32]map[uint16]interface{}
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
		binary.BigEndian.PutUint16(header[0:2], config.TemplateSetID)
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

func NewTemplateSet() *templateSet {
	return &templateSet{
		make(map[uint32][]uint16),
	}
}

func NewDataSet() *dataSet {
	return &dataSet{
		make(map[uint32]map[uint16]interface{}),
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

func (d *dataSet) AddInfoElement(enterpriseID uint32, elementID uint16, val []byte) {
	if _, exist := d.elements[enterpriseID]; !exist {
		d.elements[enterpriseID] = make(map[uint16]interface{})
	}
	// TODO: Decode data using element datatype
	d.elements[enterpriseID][elementID] = val
}

func (t *templateSet) AddInfoElement(enterpriseID uint32, elementID uint16) {
	if _, exist := t.elements[enterpriseID]; !exist {
		t.elements[enterpriseID] = make([]uint16, 0)
	}
	t.elements[enterpriseID] = append(t.elements[enterpriseID], elementID)
}