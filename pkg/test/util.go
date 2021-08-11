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

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	commonFields = []string{
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"flowEndSeconds",
		"flowEndReason",
		"packetTotalCount",
		"packetDeltaCount",
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
	}
)

type testRecord struct {
	srcIP         net.IP
	dstIP         net.IP
	srcPort       uint16
	dstPort       uint16
	proto         uint8
	flowEnd       uint32
	pktCount      uint64
	pktDelta      uint64
	srcPod        string
	dstPod        string
	dstClusterIP  net.IP
	dstSvcPort    uint16
	revPktCount   uint64
	revPktDelta   uint64
	flowType      uint8
	flowEndReason uint8
	tcpState      string
}

// getTestRecord outputs required testRecords with hardcoded values.
func getTestRecord(isSrcNode, isIPv6 bool) testRecord {
	record := testRecord{
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
	if !isSrcNode {
		record.flowEnd = uint32(1257894000)
		record.pktCount = uint64(1000)
		record.pktDelta = uint64(500)
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
		record.flowEnd = uint32(1257896000)
		record.pktCount = uint64(800)
		record.pktDelta = uint64(500)
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
	return record
}

func createTemplateSet(templateID uint16, isIPv6 bool) entities.Set {
	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, templateID)
	elements := make([]entities.InfoElementWithValue, 0)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		ie := entities.NewInfoElementWithValue(element, nil)
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
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, name := range reverseFields {
		element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	templateSet.AddRecord(elements, templateID)
	return templateSet
}

func createDataSet(templateID uint16, isSrcNode, isIPv6 bool, isMultipleRecord bool) entities.Set {
	dataSet := entities.NewSet(false)
	dataSet.PrepareSet(entities.Data, templateID)
	elements := getDataRecordElements(isSrcNode, isIPv6)
	dataSet.AddRecord(elements, templateID)
	if isMultipleRecord {
		elements = getDataRecordElements(isSrcNode, isIPv6)
		dataSet.AddRecord(elements, templateID)
	}
	return dataSet
}

func getDataRecordElements(isSrcNode, isIPv6 bool) []entities.InfoElementWithValue {
	testRec := getTestRecord(isSrcNode, isIPv6)
	elements := make([]entities.InfoElementWithValue, 0)
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
			ie = entities.NewInfoElementWithValue(element, testRec.srcIP)
		case "destinationIPv4Address", "destinationIPv6Address":
			ie = entities.NewInfoElementWithValue(element, testRec.dstIP)
		case "sourceTransportPort":
			ie = entities.NewInfoElementWithValue(element, testRec.srcPort)
		case "destinationTransportPort":
			ie = entities.NewInfoElementWithValue(element, testRec.dstPort)
		case "protocolIdentifier":
			ie = entities.NewInfoElementWithValue(element, testRec.proto)
		case "packetTotalCount":
			ie = entities.NewInfoElementWithValue(element, testRec.pktCount)
		case "packetDeltaCount":
			ie = entities.NewInfoElementWithValue(element, testRec.pktDelta)
		case "flowEndSeconds":
			ie = entities.NewInfoElementWithValue(element, testRec.flowEnd)
		case "flowEndReason":
			ie = entities.NewInfoElementWithValue(element, testRec.flowEndReason)
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
			ie = entities.NewInfoElementWithValue(element, testRec.dstClusterIP)
		case "sourcePodName":
			ie = entities.NewInfoElementWithValue(element, testRec.srcPod)
		case "destinationPodName":
			ie = entities.NewInfoElementWithValue(element, testRec.dstPod)
		case "destinationServicePort":
			ie = entities.NewInfoElementWithValue(element, testRec.dstSvcPort)
		case "flowType":
			ie = entities.NewInfoElementWithValue(element, testRec.flowType)
		case "tcpState":
			ie = entities.NewInfoElementWithValue(element, testRec.tcpState)
		}
		elements = append(elements, ie)
	}
	for _, name := range reverseFields {
		element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		var ie entities.InfoElementWithValue
		switch name {
		case "reversePacketTotalCount":
			ie = entities.NewInfoElementWithValue(element, testRec.revPktCount)
		case "reversePacketDeltaCount":
			ie = entities.NewInfoElementWithValue(element, testRec.revPktDelta)
		}
		elements = append(elements, ie)
	}
	return elements
}
