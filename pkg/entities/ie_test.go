package entities

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var macAddress, _ = net.ParseMAC("aa:bb:cc:dd:ee:ff")
var valData = []struct {
	value          interface{}
	length         int
	dataType       IEDataType
	expectedDecode interface{}
	expectedEncode interface{}
}{
	{uint8(0x1), 1, Unsigned8, uint8(0x1), []byte{0x1}},
	{uint16(123), 2, Unsigned16, uint16(123), []byte{0x0, 0x7b}},
	{uint32(1234), 4, Unsigned32, uint32(1234), []byte{0x0, 0x0, 0x4, 0xd2}},
	{uint64(12345), 8, Unsigned64, uint64(12345), []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x30, 0x39}},
	{int8(-1), 1, Signed8, int8(-1), []byte{0xff}},
	{int16(-123), 2, Signed16, int16(-123), []byte{0xff, 0x85}},
	{int32(-1234), 4, Signed32, int32(-1234), []byte{0xff, 0xff, 0xfb, 0x2e}},
	{int64(-12345), 8, Signed64, int64(-12345), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xcf, 0xc7}},
	{float32(10.6556), 4, Float32, float32(10.6556), []byte{0x41, 0x2a, 0x7d, 0x56}},
	{float64(1097.655698798798), 8, Float64, float64(1097.655698798798), []byte{0x40, 0x91, 0x26, 0x9f, 0x6f, 0x81, 0x83, 0x75}},
	{true, 1, Boolean, true, []byte{0x1}},
	{false, 1, Boolean, false, []byte{0x2}},
	{macAddress, 6, MacAddress, net.HardwareAddr([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
	{uint32(1257894000), 4, DateTimeSeconds, uint32(1257894000), []byte{0x4a, 0xf9, 0xf0, 0x70}},
	{net.ParseIP("1.2.3.4"), 4, Ipv4Address, net.IP([]byte{0x1, 0x2, 0x3, 0x4}), []byte{0x1, 0x2, 0x3, 0x4}},
	{net.ParseIP("2001:0:3238:DFE1:63::FEFB"), 16, Ipv6Address, net.IP([]byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}), []byte{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}},
}

func TestDecodeToIEDataType(t *testing.T) {
	for _, data := range valData {
		buff, err := EncodeToIEDataType(data.dataType, data.value)
		assert.Nil(t, err)
		v, err := decodeToIEDataType(data.dataType, buff)
		assert.Nil(t, err)
		assert.Equal(t, data.expectedDecode, v)
	}
	// Handle string differently since it cannot be directly write to buffer
	s := "Test String"
	v, err := decodeToIEDataType(String, []byte(s))
	assert.Nil(t, err)
	assert.Equal(t, s, v)
}

func TestEncodeToIEDataType(t *testing.T) {
	for _, data := range valData {
		var err error
		var buff []byte
		if data.dataType == Boolean {
			buff, err = EncodeToIEDataType(data.dataType, data.expectedDecode)
		} else {
			buff, err = EncodeToIEDataType(data.dataType, data.value)
		}
		assert.Nil(t, err)
		assert.Equal(t, data.expectedEncode, buff)
	}
	s := "Test"
	buff, err := EncodeToIEDataType(String, s)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x4, 0x54, 0x65, 0x73, 0x74}, buff)
}

func TestNewInfoElementWithValue(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	element := NewIPAddressInfoElement(&InfoElement{"sourceIPv4Address", 8, 18, 0, 4}, ip)
	assert.Equal(t, element.GetInfoElement().Name, "sourceIPv4Address")
	val, _ := element.GetIPAddressValue()
	assert.Equal(t, val, ip)
}
