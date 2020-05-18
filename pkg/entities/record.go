package entities

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
)

const (
	UniqueTemplateID uint16 = 256
)

// This package contains encoding of fields in the record.
// Build the record here with local buffer and write to message buffer afterwards
// Instead should we write the field directly on to message instead of have local buffer?
// To begin with, we will have local buffer in record.
// Have an interface and expose functions to user.

type Record interface {
	PrepareRecord() error
	AddInfoElement(element InfoElement, val interface{}) error
	// We can have functions for multiple elements as well.
}

type dataRecord struct {
	buff bytes.Buffer
	len  uint16
}

func NewDataRecord() *dataRecord {
	return &dataRecord{
		buff: bytes.Buffer{},
		len:  0,
	}
}

type templateRecord struct {
	buff       bytes.Buffer
	len        uint16
	fieldCount uint16
}

func NewTemplateRecord(count uint16) *templateRecord {
	return &templateRecord{
		buff:       bytes.Buffer{},
		len:        0,
		fieldCount: count,
	}
}

func (r *dataRecord) PrepareRecord() {
	// We do not have to do anything if it is data record
	return
}

func (r *dataRecord) AddInfoElement(element InfoElement, val interface{}) error {
	bytesToAppend := make([]byte, 0)
	switch dataType := element.DataType; dataType {
	case Unsigned8:
		v, ok := val.(uint8)
		if !ok {
			return fmt.Errorf("val argument is not of type uint8")
		}
		bytesToAppend = append(bytesToAppend, v)
	case Unsigned16:
		v, ok := val.(uint16)
		if !ok {
			return fmt.Errorf("val argument is not of type uint16")
		}
		binary.BigEndian.PutUint16(bytesToAppend, v)
	case Unsigned32:
		v, ok := val.(uint32)
		if !ok {
			return fmt.Errorf("val argument is not of type uint32")
		}
		binary.BigEndian.PutUint32(bytesToAppend, v)
	case Unsigned64:
		v, ok := val.(uint64)
		if !ok {
			return fmt.Errorf("val argument is not of type uint64")
		}
		binary.BigEndian.PutUint64(bytesToAppend, v)
	case Signed8:
		v, ok := val.(int8)
		if !ok {
			return fmt.Errorf("val argument is not of type int8")
		}
		bytesToAppend = append(bytesToAppend, byte(v))
	case Signed16:
		v, ok := val.(int16)
		if !ok {
			return fmt.Errorf("val argument is not of type int16")
		}
		binary.BigEndian.PutUint16(bytesToAppend, uint16(v))
	case Signed32:
		v, ok := val.(int32)
		if !ok {
			return fmt.Errorf("val argument is not of type int32")
		}
		binary.BigEndian.PutUint32(bytesToAppend, uint32(v))
	case Signed64:
		v, ok := val.(int64)
		if !ok {
			return fmt.Errorf("val argument is not of type int64")
		}
		binary.BigEndian.PutUint64(bytesToAppend, uint64(v))
	case Float32:
		v, ok := val.(float32)
		if !ok {
			return fmt.Errorf("val argument is not of type float32")
		}
		binary.BigEndian.PutUint32(bytesToAppend, math.Float32bits(v))
	case Float64:
		v, ok := val.(float64)
		if !ok {
			return fmt.Errorf("val argument is not of type float64")
		}
		binary.BigEndian.PutUint64(bytesToAppend, math.Float64bits(v))
	case Boolean:
		v, ok := val.(bool)
		if !ok {
			return fmt.Errorf("val argument is not of type bool")
		}
		// Following boolean spec from RFC7011
		if v {
			bytesToAppend = append(bytesToAppend, 1)
		} else {
			bytesToAppend = append(bytesToAppend, 2)
		}
	case DateTimeSeconds, DateTimeMilliseconds:
		// We expect time to be given in int64 as unix time type in go
		v, ok := val.(int64)
		if !ok {
			return fmt.Errorf("val argument is not of type int64")
		}
		binary.BigEndian.PutUint64(bytesToAppend, uint64(v))
		// Currently only supporting seconds and milliseconds
	case DateTimeMicroseconds, DateTimeNanoseconds:
		// TODO: RFC 7011 has extra spec for these data types. Need to follow that
		return fmt.Errorf("This API does not support micro and nano seconds types yet")
	case MacAddress:
		// Expects net.Hardware type
		v, ok := val.(net.HardwareAddr)
		if !ok {
			return fmt.Errorf("val argument is not of type net.HardwareAddr for this element")
		}
		bytesToAppend = append(bytesToAppend, []byte(v)...)
	case Ipv4Address, Ipv6Address:
		// Expects net.IP type
		v, ok := val.(net.IP)
		if !ok {
			return fmt.Errorf("val argument is not of type net.IP for this element")
		}
		bytesToAppend = append(bytesToAppend, []byte(v)...)
	case String:
		// TODO: We need to support variable length here
		return fmt.Errorf("This API does not support string and octetArray types yet")
	default:
		return fmt.Errorf("This API supports only valid information elements with datatypes given in RFC7011")
	}

	_, err := r.buff.Write(bytesToAppend)
	if err != nil {
		log.Fatalf("Error in writing field to data record: %v", err)
		return err
	}

	return nil
}

func (r *templateRecord) PrepareRecord() error {
	// Add Template Record Header
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], UniqueTemplateID)
	binary.BigEndian.PutUint16(header[2:4], r.fieldCount)

	_, err := r.buff.Write(header)
	if err != nil {
		log.Fatalf("Error in writing header to template record: %v", err)
		return err
	}

	return nil
}

func (r *templateRecord) AddInfoElement(element InfoElement, val interface{}) error {
	// val could be used to specify smaller length than default? For now assert it to be nil
	if val != nil {
		return fmt.Errorf("AddInfoElement of template record cannot take value: %v. nil is expected", val)
	}
	// Add field specifier
	fieldSpecifier := make([]byte, 4, 8)
	binary.BigEndian.PutUint16(fieldSpecifier[0:2], element.ElementId)
	binary.BigEndian.PutUint16(fieldSpecifier[2:4], element.Len)
	if element.EnterpriseId != 0 {
		// Set the MSB of elementID to 1 as per RFC7011
		fieldSpecifier[0] = fieldSpecifier[0] | 0x80
		bytesToAppend := make([]byte, 4)
		binary.BigEndian.PutUint32(bytesToAppend, element.EnterpriseId)
		fieldSpecifier = append(fieldSpecifier, bytesToAppend...)
	}

	_, err := r.buff.Write(fieldSpecifier)
	if err != nil {
		log.Fatalf("Error in writing field to template record: %v", err)
		return err
	}

	return nil
}
