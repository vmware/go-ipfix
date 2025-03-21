package entities

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testTemplateID = uint16(256)

	testIPv4Addr1 = "10.0.0.1"
	testIPv4Addr2 = "10.0.0.2"
	testIPv6Addr1 = "2001:0:3238:dfe1:63::fefb"
	testIPv6Addr2 = "2001:0:3238:dfe1:63::fefc"
)

func testAddRecordIPAddresses(t testing.TB, isIPv6 bool) {
	var sourceIE, destinationIE *InfoElement
	if isIPv6 {
		sourceIE = NewInfoElement("sourceIPv6Address", 27, 19, 0, 16)
		destinationIE = NewInfoElement("destinationIPv6Address", 28, 19, 0, 16)
	} else {
		sourceIE = NewInfoElement("sourceIPv4Address", 8, 18, 0, 4)
		destinationIE = NewInfoElement("destinationIPv4Address", 12, 18, 0, 4)
	}

	// Test with template record
	elements := []InfoElementWithValue{
		NewIPAddressInfoElement(sourceIE, nil),
		NewIPAddressInfoElement(destinationIE, nil),
	}
	newSet := NewSet(false)
	require.NoError(t, newSet.PrepareSet(Template, testTemplateID))
	require.NoError(t, newSet.AddRecord(elements, 256))
	records := newSet.GetRecords()
	require.NotEmpty(t, records)
	record := records[0]
	if isIPv6 {
		_, _, exist := record.GetInfoElementWithValue("sourceIPv6Address")
		assert.Equal(t, true, exist)
		_, _, exist = record.GetInfoElementWithValue("destinationIPv6Address")
		assert.Equal(t, true, exist)
	} else {
		_, _, exist := record.GetInfoElementWithValue("sourceIPv4Address")
		assert.Equal(t, true, exist)
		_, _, exist = record.GetInfoElementWithValue("destinationIPv4Address")
		assert.Equal(t, true, exist)
	}
	newSet.ResetSet()

	// Test with data record
	require.NoError(t, newSet.PrepareSet(Data, testTemplateID))
	var ip1, ip2 net.IP
	if isIPv6 {
		ip1 = net.ParseIP(testIPv6Addr1)
		ip2 = net.ParseIP(testIPv6Addr2)
	} else {
		ip1 = net.ParseIP(testIPv4Addr1).To4()
		ip2 = net.ParseIP(testIPv4Addr2).To4()
	}
	elements = []InfoElementWithValue{
		NewIPAddressInfoElement(sourceIE, ip1),
		NewIPAddressInfoElement(destinationIE, ip2),
	}
	require.NoError(t, newSet.AddRecord(elements, 256))
	expectedBuf := make([]byte, 0, len(ip1)+len(ip2))
	expectedBuf = append(expectedBuf, ip1...)
	expectedBuf = append(expectedBuf, ip2...)
	require.Len(t, newSet.GetRecords(), 1)
	buf, err := newSet.GetRecords()[0].GetBuffer()
	require.NoError(t, err)
	assert.Equal(t, expectedBuf, buf)
}

func TestAddRecordIPAddresses(t *testing.T) {
	t.Run("ipv4", func(t *testing.T) { testAddRecordIPAddresses(t, false) })
	t.Run("ipv6", func(t *testing.T) { testAddRecordIPAddresses(t, true) })
}

func BenchmarkAddRecordIPAddresses(b *testing.B) {
	bench := func(b *testing.B, isIPv6 bool) {
		for i := 0; i < b.N; i++ {
			testAddRecordIPAddresses(b, isIPv6)
		}
	}
	b.Run("ipv4", func(b *testing.B) { bench(b, false) })
	b.Run("ipv6", func(b *testing.B) { bench(b, true) })
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
	ie1 := NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewIPAddressInfoElement(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(true)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, testTemplateID)
	assert.Equal(t, 2, len(newSet.GetRecords()[0].GetOrderedElementList()))
}

func TestGetNumberOfRecords(t *testing.T) {
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewIPAddressInfoElement(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	elements = append(elements, ie1, ie2)
	newSet := NewSet(true)
	err := newSet.PrepareSet(Template, testTemplateID)
	assert.NoError(t, err)
	newSet.AddRecord(elements, testTemplateID)
	assert.Equal(t, uint32(1), newSet.GetNumberOfRecords())
}

func TestSet_UpdateLenInHeader(t *testing.T) {
	elements := make([]InfoElementWithValue, 0)
	ie1 := NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := NewIPAddressInfoElement(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
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

func TestMakeTemplateSet(t *testing.T) {
	ie1 := NewInfoElement("sourceIPv4Address", 8, 18, 0, 4)
	ie2 := NewInfoElement("destinationIPv4Address", 12, 18, 0, 4)
	s, err := MakeTemplateSet(testTemplateID, []*InfoElement{ie1, ie2})
	require.NoError(t, err)
	assert.Equal(t, Template, s.setType)
	require.Len(t, s.records, 1)
	assert.Equal(t, map[string]interface{}{
		"sourceIPv4Address":      net.IP(nil),
		"destinationIPv4Address": net.IP(nil),
	}, s.records[0].GetElementMap())
}

func TestMakeDataSet(t *testing.T) {
	ie1 := NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP(testIPv4Addr1))
	ie2 := NewIPAddressInfoElement(NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP(testIPv4Addr2))
	elements := []InfoElementWithValue{ie1, ie2}
	s, err := MakeDataSet(testTemplateID, elements)
	require.NoError(t, err)
	assert.Equal(t, Data, s.setType)
	require.Len(t, s.records, 1)
	assert.Equal(t, elements, s.records[0].GetOrderedElementList())
}

func BenchmarkSet(b *testing.B) {
	const (
		numRecords = 10
		templateID = 256
	)

	sourceIE := NewInfoElement("sourceIPv4Address", 8, 18, 0, 4)
	destinationIE := NewInfoElement("destinationIPv4Address", 12, 18, 0, 4)

	records := make([]Record, numRecords)
	for idx := range records {
		records[idx] = NewDataRecordFromElements(
			templateID,
			[]InfoElementWithValue{
				NewIPAddressInfoElement(sourceIE, net.ParseIP(testIPv4Addr1)),
				NewIPAddressInfoElement(destinationIE, net.ParseIP(testIPv4Addr2)),
			},
		)
	}

	set := NewSet(false)

	addRecords := func() {
		for _, record := range records {
			set.AddRecordV3(record)
		}
	}

	b.ResetTimer()
	for range b.N {
		set.ResetSet()
		set.PrepareSet(Data, templateID)
		addRecords()
	}
}
