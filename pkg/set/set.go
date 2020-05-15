package set

import (
	"bytes"
	"encoding/binary"
	"github.com/srikartati/go-ipfixlib/pkg/template"
	"log"
)

type SetOrRecordType uint8

const (
	Template SetOrRecordType = iota
	Data
	// Add OptionsTemplate too when it is supported
)

// Do not expose set to IPFIX library user
// Not creating any interface plan to use same struct for Template and Data Records

type Set struct {
	buffer  bytes.Buffer
	setType SetOrRecordType
}

func NewSet() *Set {
	return &Set{
		buffer:   bytes.Buffer{},
		setType:  nil,
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
		binary.BigEndian.PutUint16(header[0:2], template.UniqueTemplateID)
	}
	// Write the set header to msg buffer
	_, err := s.buffer.Write(header)
	if err != nil {
		log.Fatalf("Error in writing header to message buffer: %v", err)
		return err
	}
	// set the setType
	s.setType = setType
	return nil
}

func (s *Set) FinishSet() {
	// Add padding if required and add length to the message
}
