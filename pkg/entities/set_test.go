package entities

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddRecord(t *testing.T) {
	// Test with template set
	elements := make([]*InfoElementWithValue, 0)
	ie1 := NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	set := NewSet(Template, uint16(256), true)
	set.AddRecord(elements, 256)
	assert.Equal(t, ie1, set.GetRecords()[0].GetInfoElements()[0])
	assert.Equal(t, ie2, set.GetRecords()[0].GetInfoElements()[1])
	// Test with data set
	set = NewSet(Data, uint16(259), false)
	elements = make([]*InfoElementWithValue, 0)
	ie1 = NewInfoElementWithValue(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1"))
	ie2 = NewInfoElementWithValue(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2"))
	elements = append(elements, ie1, ie2)
	set.AddRecord(elements, 259)
	assert.Equal(t, uint32(167772161), set.GetRecords()[0].GetInfoElements()[0].Value)
	assert.Equal(t, uint32(167772162), set.GetRecords()[0].GetInfoElements()[1].Value)
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
