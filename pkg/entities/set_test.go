package entities

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddRecordIPv4Addresses(t *testing.T) {
	// Test with template set
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	set := NewSet(Template, uint16(256), true)
	set.AddRecord(elements, 256)
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("sourceIPv4Address"))
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("destinationIPv4Address"))
	// Test with data set
	set = NewSet(Data, uint16(256), false)
	elements = make([]*InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1"))
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2"))
	elements = append(elements, ie1, ie2)
	set.AddRecord(elements, 256)
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("sourceIPv4Address"))
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("destinationIPv4Address"))
	assert.Equal(t, net.IP([]byte{0xa, 0x0, 0x0, 0x1}), set.GetRecords()[0].GetInfoElement("sourceIPv4Address").Value)
	assert.Equal(t, net.IP([]byte{0xa, 0x0, 0x0, 0x2}), set.GetRecords()[0].GetInfoElement("destinationIPv4Address").Value)
}

func TestAddRecordIPv6Addresses(t *testing.T) {
	// Test with template set
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), nil)
	elements = append(elements, ie1, ie2)
	set := NewSet(Template, uint16(256), true)
	set.AddRecord(elements, 256)
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("sourceIPv6Address"))
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("destinationIPv6Address"))
	// Test with data set
	set = NewSet(Data, uint16(256), false)
	elements = make([]*InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv6Address", 27, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv6Address", 28, 19, 0, 16), net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
	elements = append(elements, ie1, ie2)
	set.AddRecord(elements, 256)
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("sourceIPv6Address"))
	assert.Equal(t, true, set.GetRecords()[0].ContainsInfoElement("destinationIPv6Address"))
	assert.Equal(t, net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}), set.GetRecords()[0].GetInfoElement("sourceIPv6Address").Value)
	assert.Equal(t, net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfc}), set.GetRecords()[0].GetInfoElement("destinationIPv6Address").Value)
}

func TestGetSetType(t *testing.T) {
	assert.Equal(t, Template, NewSet(Template, uint16(256), true).GetSetType())
	assert.Equal(t, Data, NewSet(Data, uint16(258), true).GetSetType())
}

func TestGetBuffer(t *testing.T) {
	assert.Equal(t, 0, NewSet(Template, uint16(256), true).GetBuffer().Len())
	assert.Equal(t, 4, NewSet(Template, uint16(257), false).GetBuffer().Len())
	assert.Equal(t, 0, NewSet(Data, uint16(258), true).GetBuffer().Len())
	assert.Equal(t, 4, NewSet(Data, uint16(259), false).GetBuffer().Len())
}

func TestGetBuffLen(t *testing.T) {
	assert.Equal(t, uint16(0), NewSet(Template, uint16(256), true).GetBuffLen())
	assert.Equal(t, uint16(4), NewSet(Template, uint16(257), false).GetBuffLen())
	assert.Equal(t, uint16(0), NewSet(Data, uint16(258), true).GetBuffLen())
	assert.Equal(t, uint16(4), NewSet(Data, uint16(259), false).GetBuffLen())
}

func TestGetRecords(t *testing.T) {
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	set := NewSet(Template, uint16(256), true)
	set.AddRecord(elements, 256)
	assert.Equal(t, 2, len(set.GetRecords()[0].GetInfoElements()))
}

func TestGetNumberOfRecords(t *testing.T) {
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	set := NewSet(Template, uint16(256), true)
	set.AddRecord(elements, 256)
	assert.Equal(t, uint32(1), set.GetNumberOfRecords())
}

func TestFinishSet(t *testing.T) {
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	set1 := NewSet(Template, uint16(256), true)
	set2 := NewSet(Template, uint16(257), false)
	set2.AddRecord(elements, 256)
	assert.Equal(t, uint16(0), set1.GetBuffLen())
	assert.Equal(t, uint16(16), set2.GetBuffLen())
	set1.FinishSet()
	set2.FinishSet()
	assert.Equal(t, uint16(0), set1.GetBuffLen())
	assert.Equal(t, uint16(0), set2.GetBuffLen())
}
