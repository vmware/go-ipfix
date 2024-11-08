// Copyright 2021 VMware, Inc.
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

package test

import (
	"net"
	"time"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	// First release of Antrea (v0.1.0) at KubeCon NA 2019 (San Diego) :)
	sanDiegoLocation, _ = time.LoadLocation("America/Los_Angeles")
	testTime            = time.Date(2019, time.November, 18, 11, 26, 2, 0, sanDiegoLocation)
)

var (
	commonFields = []string{
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"flowStartSeconds",
		"flowEndSeconds",
		"flowEndReason",
		"packetTotalCount",
		"packetDeltaCount",
		"octetTotalCount",
	}
	ianaIPv4Fields = []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
	}
	ianaIPv6Fields = []string{
		"sourceIPv6Address",
		"destinationIPv6Address",
	}
	antreaCommonFields = []string{
		"sourcePodName",
		"destinationPodName",
		"destinationServicePort",
		"flowType",
		"tcpState",
	}
	antreaIPv4 = []string{
		"destinationClusterIPv4",
	}
	antreaIPv6 = []string{
		"destinationClusterIPv6",
	}
	reverseFields = []string{
		"reversePacketTotalCount",
		"reversePacketDeltaCount",
		"reverseOctetTotalCount",
	}
	// same for IPv4 and IPv6
	numFields = len(commonFields) + len(ianaIPv4Fields) + len(antreaCommonFields) + len(antreaIPv4) + len(reverseFields)
)

// will be initialized in init() after loading the registry
var templatePacketIPv4, dataPacket1IPv4, dataPacket2IPv4, templatePacketIPv6, dataPacket1IPv6, dataPacket2IPv6 []byte

type testRecord struct {
	isIPv6        bool
	srcIP         net.IP
	dstIP         net.IP
	srcPort       uint16
	dstPort       uint16
	proto         uint8
	flowStart     uint32
	flowEnd       uint32
	pktCount      uint64
	pktDelta      uint64
	srcPod        string
	dstPod        string
	dstClusterIP  net.IP
	dstSvcPort    uint16
	revPktCount   uint64
	revPktDelta   uint64
	bytCount      uint64
	revBytCount   uint64
	flowType      uint8
	flowEndReason uint8
	tcpState      string
}

type testRecordOptions func(*testRecord)

// getTestRecord outputs required testRecords with hardcoded values.
func getTestRecord(isSrcNode, isIPv6 bool, options ...testRecordOptions) *testRecord {
	record := testRecord{
		isIPv6:        isIPv6,
		srcPort:       uint16(1234),
		dstPort:       uint16(5678),
		proto:         uint8(6),
		flowType:      registry.FlowTypeInterNode,
		flowEndReason: registry.ActiveTimeoutReason,
		tcpState:      "ESTABLISHED",
	}
	if !isIPv6 {
		record.srcIP = net.ParseIP("10.0.0.1").To4()
		record.dstIP = net.ParseIP("10.0.0.2").To4()
	} else {
		record.srcIP = net.ParseIP("2001:0:3238:DFE1:63::FEFB")
		record.dstIP = net.ParseIP("2001:0:3238:DFE1:63::FEFC")
	}
	for _, option := range options {
		option(&record)
	}
	record.flowStart = uint32(1257893000)
	if !isSrcNode {
		record.flowEnd = uint32(1257896000)
		record.pktCount = uint64(1000)
		record.pktDelta = uint64(500)
		record.bytCount = uint64(1000000)
		record.revBytCount = uint64(400000)
		record.dstSvcPort = uint16(0)
		record.srcPod = ""
		record.dstPod = "pod2"
		record.revPktCount = uint64(400)
		record.revPktDelta = uint64(200)
		if !isIPv6 {
			record.dstClusterIP = net.ParseIP("0.0.0.0")
		} else {
			record.dstClusterIP = net.ParseIP("::")
		}
	} else {
		record.flowEnd = uint32(1257894000)
		record.pktCount = uint64(800)
		record.pktDelta = uint64(500)
		record.bytCount = uint64(800000)
		record.revBytCount = uint64(300000)
		record.dstSvcPort = uint16(4739)
		record.srcPod = "pod1"
		record.dstPod = ""
		record.revPktCount = uint64(300)
		record.revPktDelta = uint64(150)
		if !isIPv6 {
			record.dstClusterIP = net.ParseIP("10.0.0.3")
		} else {
			record.dstClusterIP = net.ParseIP("2001:0:3238:BBBB:63::AAAA")
		}
	}
	return &record
}

func createTemplateSet(templateID uint16, isIPv6 bool) entities.Set {
	ies := make([]*entities.InfoElement, 0, numFields)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		ie, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		ies = append(ies, ie)
	}
	antreaFields := antreaCommonFields
	if !isIPv6 {
		antreaFields = append(antreaFields, antreaIPv4...)
	} else {
		antreaFields = append(antreaFields, antreaIPv6...)
	}
	for _, name := range antreaFields {
		ie, _ := registry.GetInfoElement(name, registry.AntreaEnterpriseID)
		ies = append(ies, ie)
	}
	for _, name := range reverseFields {
		ie, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		ies = append(ies, ie)
	}
	templateSet, _ := entities.MakeTemplateSet(templateID, ies)
	return templateSet
}

func createDataSetForTestRecord(templateID uint16, testRec *testRecord, count int) entities.Set {
	dataSet := entities.NewSet(false)
	for i := 0; i < count; i++ {
		dataSet.PrepareSet(entities.Data, templateID)
		elements := getDataRecordElements(testRec)
		dataSet.AddRecord(elements, templateID)
	}
	return dataSet
}

func createDataSet(templateID uint16, isSrcNode, isIPv6 bool, isMultipleRecord bool) entities.Set {
	testRec := getTestRecord(isSrcNode, isIPv6)
	count := 1
	if isMultipleRecord {
		count = 2
	}
	return createDataSetForTestRecord(templateID, testRec, count)
}

func getDataRecordElements(testRec *testRecord) []entities.InfoElementWithValue {
	isIPv6 := testRec.isIPv6
	elements := make([]entities.InfoElementWithValue, 0, numFields)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "sourceIPv4Address", "sourceIPv6Address":
			ie = entities.NewIPAddressInfoElement(element, testRec.srcIP)
		case "destinationIPv4Address", "destinationIPv6Address":
			ie = entities.NewIPAddressInfoElement(element, testRec.dstIP)
		case "sourceTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, testRec.srcPort)
		case "destinationTransportPort":
			ie = entities.NewUnsigned16InfoElement(element, testRec.dstPort)
		case "protocolIdentifier":
			ie = entities.NewUnsigned8InfoElement(element, testRec.proto)
		case "packetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.pktCount)
		case "packetDeltaCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.pktDelta)
		case "octetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.bytCount)
		case "flowStartSeconds":
			ie = entities.NewDateTimeSecondsInfoElement(element, testRec.flowStart)
		case "flowEndSeconds":
			ie = entities.NewDateTimeSecondsInfoElement(element, testRec.flowEnd)
		case "flowEndReason":
			ie = entities.NewUnsigned8InfoElement(element, testRec.flowEndReason)
		}
		elements = append(elements, ie)
	}
	antreaFields := antreaCommonFields
	if !isIPv6 {
		antreaFields = append(antreaFields, antreaIPv4...)
	} else {
		antreaFields = append(antreaFields, antreaIPv6...)
	}
	for _, name := range antreaFields {
		element, _ := registry.GetInfoElement(name, registry.AntreaEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "destinationClusterIPv4", "destinationClusterIPv6":
			ie = entities.NewIPAddressInfoElement(element, testRec.dstClusterIP)
		case "sourcePodName":
			ie = entities.NewStringInfoElement(element, testRec.srcPod)
		case "destinationPodName":
			ie = entities.NewStringInfoElement(element, testRec.dstPod)
		case "destinationServicePort":
			ie = entities.NewUnsigned16InfoElement(element, testRec.dstSvcPort)
		case "flowType":
			ie = entities.NewUnsigned8InfoElement(element, testRec.flowType)
		case "tcpState":
			ie = entities.NewStringInfoElement(element, testRec.tcpState)
		}
		elements = append(elements, ie)
	}
	for _, name := range reverseFields {
		element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "reversePacketTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.revPktCount)
		case "reversePacketDeltaCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.revPktDelta)
		case "reverseOctetTotalCount":
			ie = entities.NewUnsigned64InfoElement(element, testRec.revBytCount)
		}
		elements = append(elements, ie)
	}
	return elements
}

func getTestTemplatePacket(isIPv6 bool) []byte {
	set := createTemplateSet(1 /* templateID */, isIPv6)
	bytes, err := exporter.CreateIPFIXMsg(set, 1 /* obsDomainID */, 0 /* seqNumber */, testTime)
	if err != nil {
		panic("failed to create test template packet")
	}
	return bytes
}

func getTestDataPacket(isSrcNode bool, isIPv6 bool) []byte {
	set := createDataSet(1 /* templateID */, isSrcNode, isIPv6, false /* isMultipleRecord */)
	bytes, err := exporter.CreateIPFIXMsg(set, 1 /* obsDomainID */, 0 /* seqNumber */, testTime)
	if err != nil {
		panic("failed to create test data packet")
	}
	return bytes
}

func init() {
	// Load the global registry
	registry.LoadRegistry()

	templatePacketIPv4 = getTestTemplatePacket(false)
	dataPacket1IPv4 = getTestDataPacket(true, false)
	dataPacket2IPv4 = getTestDataPacket(false, false)
	templatePacketIPv6 = getTestTemplatePacket(true)
	dataPacket1IPv6 = getTestDataPacket(true, true)
	dataPacket2IPv6 = getTestDataPacket(false, true)
}
