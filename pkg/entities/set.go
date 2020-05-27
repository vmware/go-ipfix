package entities

import (
	"bytes"
	"encoding/binary"
	"log"
)

type SetOrRecordType uint8

const (
	Template SetOrRecordType = iota
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
	setType SetOrRecordType
}

func NewSet(buffer *bytes.Buffer) *Set {
	return &Set{
		buffer:  buffer,
		currLen: 0,
		setType: Undefined,
	}
}

func (s *Set) CreateNewSet(setType SetOrRecordType) error {
	// Create the set header and append it
	header := make([]byte, 4)
	if setType == Template {
		binary.BigEndian.PutUint16(header[0:2], 2)
	} else if setType == Data {
		// Supporting only one templateID per exporting process
		// TODO: Add support to multiple template IDs
		binary.BigEndian.PutUint16(header[0:2], UniqueTemplateID)
	}
	// Write the set header to msg buffer
	_, err := s.buffer.Write(header)
	if err != nil {
		log.Fatalf("Error in writing header to message buffer: %v", err)
		return err
	}
	// set the setType and update set length
	s.setType = setType
	s.currLen = s.currLen + uint16(len(header))

	return nil
}

func (s *Set) GetBuffLen() uint16 {
	return s.currLen
}

func (s *Set) GetSetType() SetOrRecordType {
	return s.setType
}

func (s *Set) WriteRecordToSet(recBuffer *[]byte) error {
	_, err := s.buffer.Write(*recBuffer)
	if err != nil {
		return err
	}
	// Update the length of set
	s.currLen = s.currLen + uint16(len(*recBuffer))
	return nil
}

func (s *Set) FinishSet() {
	// Add length to the message
	byteSlice := s.buffer.Bytes()
	setOffset := s.buffer.Len() - int(s.currLen)
	binary.BigEndian.PutUint16(byteSlice[setOffset+2:setOffset+4], s.currLen)
	// TODO:Add padding if required
	// Reset the length
	s.currLen = 0
}
