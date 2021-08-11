package entities

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testTemplateID = uint16(256)
)

func TestAddRecordIPv4Addresses(t *testing.T) {
	// Test with template encodingSet
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	encodingSet := NewSet(false)
	err := encodingSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	encodingSet.AddRecord(elements, 256)
	_, _, exist := encodingSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	_, _, exist = encodingSet.GetRecords()[0].GetInfoElementWithValue("destinationIPv4Address")
	assert.Equal(t, true, exist)
	encodingSet.ResetSet()
	// Test with data encodingSet
	err = encodingSet.PrepareSet(Data, testTemplateID)
	assert.NoError(t, err)
	elements = make([]InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1").To4())
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2").To4())
	elements = append(elements, ie1, ie2)
	err = encodingSet.AddRecord(elements, 256)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xa, 0x0, 0x0, 0x1, 0xa, 0x0, 0x0, 0x2}, encodingSet.GetRecords()[0].GetBuffer())
}

func TestAddRecordIPv6Addresses(t *testing.T) {
	// Test with template record
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(false)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, 256)
	assert.Equal(t, []byte{0x1, 0x0, 0x0, 0x2, 0x0, 0x1b, 0x0, 0x10, 0x0, 0x1c, 0x0, 0x10}, newSet.GetRecords()[0].GetBuffer())
	newSet.ResetSet()
	// Test with data record
	err = newSet.PrepareSet(Data, testTemplateID)
	assert.NoError(t, err)
	elements = make([]InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
	elements = append(elements, ie1, ie2)
	newSet.AddRecord(elements, 256)
	srcIP := []byte(net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
	dstIP := []byte(net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
	assert.Equal(t, append(srcIP, dstIP...), newSet.GetRecords()[0].GetBuffer())
}

func TestGetSetType(t *testing.T) {
	newSet := NewSet(true)
	_ = newSet.PrepareSet(Template, testTemplateID)
	assert.Equal(t, Template, newSet.GetSetType())
	newSet.ResetSet()
	_ = newSet.PrepareSet(Data, testTemplateID)
	assert.Equal(t, Data, newSet.GetSetType())
}

func TestGetHeaderBuffer(t *testing.T) {
	decodingSet := NewSet(true)
	err := decodingSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(decodingSet.GetHeaderBuffer()))

	encodingSet := NewSet(false)
	err = encodingSet.PrepareSet(Template, uint16(257))
	assert.NoError(t, err)
	assert.Equal(t, 4, len(encodingSet.GetHeaderBuffer()))
}

func TestGetRecords(t *testing.T) {
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(true)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, testTemplateID)
	assert.Equal(t, 2, len(newSet.GetRecords()[0].GetOrderedElementList()))
}

func TestGetNumberOfRecords(t *testing.T) {
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(true)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, testTemplateID)
	assert.Equal(t, uint32(1), newSet.GetNumberOfRecords())
}

func TestSet_UpdateLenInHeader(t *testing.T) {
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	setForDecoding := NewSet(true)
	err := setForDecoding.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	setForEncoding := NewSet(false)
	err = setForEncoding.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	setForEncoding.AddRecord(elements, testTemplateID)
	setForDecoding.UpdateLenInHeader()
	setForEncoding.UpdateLenInHeader()
	// Nothing should be written in setForDecoding
	assert.Equal(t, 0, len(setForDecoding.GetHeaderBuffer()))
	// Check the bytes in the header for set length
	assert.Equal(t, uint16(setForEncoding.GetSetLength()), binary.BigEndian.Uint16(setForEncoding.GetHeaderBuffer()[2:4]))
}
