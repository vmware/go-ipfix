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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var uniqueTemplateID uint16 = 256

func TestPrepareRecord(t *testing.T) {
	prepareRecordTests := []struct {
		record    Record
		expectLen uint16
		expectErr error
	}{
		{NewDataRecord(uniqueTemplateID, 1, 0), 0, nil},
		{NewTemplateRecord(uniqueTemplateID, 1), 4, nil},
	}

	for _, test := range prepareRecordTests {
		actualErr := test.record.PrepareRecord()
		if actualErr != test.expectErr {
			t.Errorf("Prepare record expects no error, but got %v", actualErr)
		}
	}
}

func TestAddInfoElements(t *testing.T) {
	testIEs := []*InfoElement{
		// Test element of each type
		NewInfoElement("protocolIdentifier", 4, 1, 0, 1),  // unsigned8
		NewInfoElement("sourceTransportPort", 7, 2, 0, 2), // unsigned16
		NewInfoElement("ingressInterface", 10, 3, 0, 4),   // unsigned32
		NewInfoElement("packetDeltaCount", 2, 4, 0, 8),    // unsigned64
		// No elements of signed8, signed16 and signed64 in IANA registry
		NewInfoElement("mibObjectValueInteger", 434, 7, 0, 4), // signed32
		// No elements of float32 in IANA registry
		NewInfoElement("samplingProbability", 311, 10, 0, 8),     // float64
		NewInfoElement("dataRecordsReliability", 276, 11, 0, 1),  // boolean
		NewInfoElement("sourceMacAddress", 56, 12, 0, 6),         // mac address
		NewInfoElement("sourceIPv4Address", 8, 18, 0, 4),         // IP Address
		NewInfoElement("interfaceDescription", 83, 13, 0, 65535), // String
		NewInfoElement("flowStartSeconds", 150, 14, 0, 4),        // dateTimeSeconds
		NewInfoElement("flowStartMilliseconds", 152, 15, 0, 8),   // dateTimeMilliseconds
	}
	macAddress, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	type valData struct {
		proto              uint8
		srcPort            uint16
		ingressInt         uint32
		pktCount           uint64
		minObjVal          int32
		samplingProb       float64
		dataReliable       bool
		macAddr            net.HardwareAddr
		ipAddr             net.IP
		stringVal          string
		flowStartSecs      uint32
		flowStartMillisecs uint64
	}
	values := valData{
		uint8(0x1),                  // ICMP proto
		uint16(443),                 // https port
		uint32(1000),                // ingress interface ID
		uint64(100000),              // packet count
		int32(-12345),               // mibObjectValueInteger
		0.856,                       // samplingProbability
		true,                        // dataRecordsReliability
		macAddress,                  // mac address
		net.ParseIP("1.2.3.4"),      // IP Address
		"My Interface in IPFIX lib", // String
		uint32(time.Now().Unix()),   // dateTimeSeconds
		uint64(time.Now().Unix()),   // dateTimeMilliseconds
	}
	addIETests := []struct {
		record  Record
		ieList  []*InfoElement
		valList valData
	}{
		{NewTemplateRecord(uniqueTemplateID, 12), testIEs, valData{}},
		{NewDataRecord(uniqueTemplateID, len(testIEs), 0), testIEs, values},
	}

	for i, test := range addIETests {
		for _, testIE := range test.ieList {
			var actualErr error
			if i == 0 {
				// For template record
				ie, _ := DecodeAndCreateInfoElementWithValue(testIE, nil)
				actualErr = test.record.AddInfoElement(ie)
			} else {
				// For data record
				var ie InfoElementWithValue
				switch testIE.Name {
				case "protocolIdentifier":
					ie = NewUnsigned8InfoElement(testIE, test.valList.proto)
				case "sourceTransportPort":
					ie = NewUnsigned16InfoElement(testIE, test.valList.srcPort)
				case "ingressInterface":
					ie = NewUnsigned32InfoElement(testIE, test.valList.ingressInt)
				case "packetDeltaCount":
					ie = NewUnsigned64InfoElement(testIE, test.valList.pktCount)
				case "mibObjectValueInteger":
					ie = NewSigned32InfoElement(testIE, test.valList.minObjVal)
				case "samplingProbability":
					ie = NewFloat64InfoElement(testIE, test.valList.samplingProb)
				case "dataRecordsReliability":
					ie = NewBoolInfoElement(testIE, test.valList.dataReliable)
				case "flowStartSeconds":
					ie = NewDateTimeSecondsInfoElement(testIE, test.valList.flowStartSecs)
				case "flowStartMilliseconds":
					ie = NewDateTimeMillisecondsInfoElement(testIE, test.valList.flowStartMillisecs)
				case "sourceMacAddress":
					ie = NewMacAddressInfoElement(testIE, test.valList.macAddr)
				case "sourceIPv4Address":
					ie = NewIPAddressInfoElement(testIE, test.valList.ipAddr)
				case "interfaceDescription":
					ie = NewStringInfoElement(testIE, test.valList.stringVal)
				}
				actualErr = test.record.AddInfoElement(ie)
			}
			assert.Equal(t, nil, actualErr, "Error returned is not nil")
		}
		// go test -v to see data buffer in hex format
		buf, err := test.record.GetBuffer()
		require.NoError(t, err)
		if i == 0 {
			t.Logf("template record %x", buf)
		} else {
			t.Logf("data record %x", buf)
		}
	}
}

func TestGetInfoElementWithValue(t *testing.T) {
	templateRec := NewTemplateRecord(256, 1)
	templateRec.orderedElementList = make([]InfoElementWithValue, 0)
	ie := NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	templateRec.orderedElementList = append(templateRec.orderedElementList, ie)
	_, _, exist := templateRec.GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	_, _, exist = templateRec.GetInfoElementWithValue("destinationIPv4Address")
	assert.Equal(t, false, exist)
	dataRec := NewDataRecord(256, 1, 0)
	dataRec.orderedElementList = make([]InfoElementWithValue, 0)
	ie = NewIPAddressInfoElement(NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1"))
	dataRec.orderedElementList = append(dataRec.orderedElementList, ie)
	infoElementWithValue, _, _ := dataRec.GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, net.ParseIP("10.0.0.1"), infoElementWithValue.GetIPAddressValue())
	infoElementWithValue, _, _ = dataRec.GetInfoElementWithValue("destinationIPv4Address")
	assert.Empty(t, infoElementWithValue)
}

func TestGetElementMap(t *testing.T) {
	ieList := []*InfoElement{
		// Test element of each type
		NewInfoElement("protocolIdentifier", 4, 1, 0, 1),  // unsigned8
		NewInfoElement("sourceTransportPort", 7, 2, 0, 2), // unsigned16
		NewInfoElement("ingressInterface", 10, 3, 0, 4),   // unsigned32
		NewInfoElement("packetDeltaCount", 2, 4, 0, 8),    // unsigned64
		// No elements of signed8, signed16 and signed64 in IANA registry
		NewInfoElement("mibObjectValueInteger", 434, 7, 0, 4), // signed32
		// No elements of float32 in IANA registry
		NewInfoElement("samplingProbability", 311, 10, 0, 8),     // float64
		NewInfoElement("dataRecordsReliability", 276, 11, 0, 1),  // boolean
		NewInfoElement("sourceMacAddress", 56, 12, 0, 6),         // mac address
		NewInfoElement("sourceIPv4Address", 8, 18, 0, 4),         // IP Address
		NewInfoElement("interfaceDescription", 83, 13, 0, 65535), // String
		NewInfoElement("flowStartSeconds", 150, 14, 0, 4),        // dateTimeSeconds
		NewInfoElement("flowStartMilliseconds", 152, 15, 0, 8),   // dateTimeMilliseconds
	}
	macAddress, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	type valData struct {
		proto              uint8
		srcPort            uint16
		ingressInt         uint32
		pktCount           uint64
		minObjVal          int32
		samplingProb       float64
		dataReliable       bool
		macAddr            net.HardwareAddr
		ipAddr             net.IP
		stringVal          string
		flowStartSecs      uint32
		flowStartMillisecs uint64
	}
	valList := valData{
		uint8(0x1),                  // ICMP proto
		uint16(443),                 // https port
		uint32(1000),                // ingress interface ID
		uint64(100000),              // packet count
		int32(-12345),               // mibObjectValueInteger
		0.856,                       // samplingProbability
		true,                        // dataRecordsReliability
		macAddress,                  // mac address
		net.ParseIP("1.2.3.4"),      // IP Address
		"My Interface in IPFIX lib", // String
		uint32(time.Now().Unix()),   // dateTimeSeconds
		uint64(time.Now().Unix()),   // dateTimeMilliseconds
	}
	record := NewDataRecord(uniqueTemplateID, len(ieList), 0)

	for _, testIE := range ieList {
		var ie InfoElementWithValue
		switch testIE.Name {
		case "protocolIdentifier":
			ie = NewUnsigned8InfoElement(testIE, valList.proto)
		case "sourceTransportPort":
			ie = NewUnsigned16InfoElement(testIE, valList.srcPort)
		case "ingressInterface":
			ie = NewUnsigned32InfoElement(testIE, valList.ingressInt)
		case "packetDeltaCount":
			ie = NewUnsigned64InfoElement(testIE, valList.pktCount)
		case "mibObjectValueInteger":
			ie = NewSigned32InfoElement(testIE, valList.minObjVal)
		case "samplingProbability":
			ie = NewFloat64InfoElement(testIE, valList.samplingProb)
		case "dataRecordsReliability":
			ie = NewBoolInfoElement(testIE, valList.dataReliable)
		case "flowStartSeconds":
			ie = NewDateTimeSecondsInfoElement(testIE, valList.flowStartSecs)
		case "flowStartMilliseconds":
			ie = NewDateTimeMillisecondsInfoElement(testIE, valList.flowStartMillisecs)
		case "sourceMacAddress":
			ie = NewMacAddressInfoElement(testIE, valList.macAddr)
		case "sourceIPv4Address":
			ie = NewIPAddressInfoElement(testIE, valList.ipAddr)
		case "interfaceDescription":
			ie = NewStringInfoElement(testIE, valList.stringVal)
		}
		record.AddInfoElement(ie)
	}
	elements := record.GetElementMap()
	assert.Equal(t, valList.proto, elements["protocolIdentifier"])
	assert.Equal(t, valList.srcPort, elements["sourceTransportPort"])
	assert.Equal(t, valList.ingressInt, elements["ingressInterface"])
	assert.Equal(t, valList.pktCount, elements["packetDeltaCount"])
	assert.Equal(t, valList.minObjVal, elements["mibObjectValueInteger"])
	assert.Equal(t, valList.samplingProb, elements["samplingProbability"])
	assert.Equal(t, valList.dataReliable, elements["dataRecordsReliability"])
	assert.Equal(t, valList.flowStartSecs, elements["flowStartSeconds"])
	assert.Equal(t, valList.flowStartMillisecs, elements["flowStartMilliseconds"])
	assert.Equal(t, valList.macAddr, elements["sourceMacAddress"])
	assert.Equal(t, valList.ipAddr, elements["sourceIPv4Address"])
	assert.Equal(t, valList.stringVal, elements["interfaceDescription"])
}
