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
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	encodingSet := NewSet(false)
	err := encodingSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	encodingSet.AddRecord(elements, 256)
	_, exist := encodingSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	_, exist = encodingSet.GetRecords()[0].GetInfoElementWithValue("destinationIPv4Address")
	assert.Equal(t, true, exist)
	encodingSet.ResetSet()
	// Test with data encodingSet
	err = encodingSet.PrepareSet(Data, testTemplateID)
	assert.NoError(t, err)
	elements = make([]*InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1").To4())
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2").To4())
	elements = append(elements, ie1, ie2)
	err = encodingSet.AddRecord(elements, 256)
	assert.NoError(t, err)
	infoElementWithValue, _ := encodingSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, net.IP([]byte{0xa, 0x0, 0x0, 0x1}), infoElementWithValue.Value)
	infoElementWithValue, _ = encodingSet.GetRecords()[0].GetInfoElementWithValue("destinationIPv4Address")
	assert.Equal(t, net.IP([]byte{0xa, 0x0, 0x0, 0x2}), infoElementWithValue.Value)
}

func TestAddRecordIPv6Addresses(t *testing.T) {
	// Test with template record
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(false)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, 256)
	_, exist := newSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.Equal(t, true, exist)
	_, exist = newSet.GetRecords()[0].GetInfoElementWithValue("destinationIPv6Address")
	assert.Equal(t, true, exist)
	newSet.ResetSet()
	// Test with data record
	err = newSet.PrepareSet(Data, testTemplateID)
	assert.NoError(t, err)
	elements = make([]*InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
	elements = append(elements, ie1, ie2)
	newSet.AddRecord(elements, 256)
	infoElementWithValue, _ := newSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.Equal(t, net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}), infoElementWithValue.Value)
	infoElementWithValue, _ = newSet.GetRecords()[0].GetInfoElementWithValue("destinationIPv6Address")
	assert.Equal(t, net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfc}), infoElementWithValue.Value)
}

func TestGetSetType(t *testing.T) {
	newSet := NewSet(true)
	_ = newSet.PrepareSet(Template, testTemplateID)
	assert.Equal(t, Template, newSet.GetSetType())
	newSet.ResetSet()
	_ = newSet.PrepareSet(Data, testTemplateID)
	assert.Equal(t, Data, newSet.GetSetType())
}

func TestGetBuffer(t *testing.T) {
	decodingSet := NewSet(true)
	err := decodingSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	assert.Equal(t, 0, decodingSet.GetBuffer().Len())
	decodingSet.ResetSet()
	err = decodingSet.PrepareSet(Template, uint16(258))
	assert.NoError(t, err)
	assert.Equal(t, 0, decodingSet.GetBuffer().Len())

	encodingSet := NewSet(false)
	err = encodingSet.PrepareSet(Template, uint16(257))
	assert.NoError(t, err)
	assert.Equal(t, 4, encodingSet.GetBuffer().Len())
	encodingSet.ResetSet()
	err = encodingSet.PrepareSet(Template, uint16(257))
	assert.NoError(t, err)
	assert.Equal(t, 4, encodingSet.GetBuffer().Len())
}

func TestGetRecords(t *testing.T) {
	elements := make([]*InfoElementWithValue, 0)
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
	elements := make([]*InfoElementWithValue, 0)
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
	elements := make([]*InfoElementWithValue, 0)
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
	assert.Equal(t, 0, setForDecoding.GetBuffer().Len())
	assert.Equal(t, 16, setForEncoding.GetBuffer().Len())
	setForDecoding.UpdateLenInHeader()
	setForEncoding.UpdateLenInHeader()
	// Nothing should be written in setForDecoding
	assert.Equal(t, 0, setForDecoding.GetBuffer().Len())
	// Check the bytes in the header for set length
	assert.Equal(t, uint16(setForEncoding.GetBuffer().Len()), binary.BigEndian.Uint16(setForEncoding.GetBuffer().Bytes()[2:4]))
}
