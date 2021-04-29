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

// +build integration

package test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func init() {
	// Load the global registry
	registry.LoadRegistry()
}

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

func TestSingleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, false, false, t)
}

func TestSingleRecordTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	// test two records: one is source node record and other one is destination node record
	testExporterToCollector(address, true, false, false, false, t)
	testExporterToCollector(address, false, false, false, false, t)
}

func TestSingleRecordTCPTransportIPv6(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "[::1]:0")
	if err != nil {
		t.Error(err)
	}
	// test two records: one is source node record and other one is destination node record
	testExporterToCollector(address, true, true, false, false, t)
	testExporterToCollector(address, false, true, false, false, t)
}

func TestSingleRecordUDPTransportIPv6(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "[::1]:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, true, false, false, t)
}

func TestMultipleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, true, false, t)
}

func TestMultipleRecordTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, true, false, t)
}

func TestTLSTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, false, true, t)
}

func TestDTLSTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, false, true, t)
}

func testExporterToCollector(address net.Addr, isSrcNode, isIPv6 bool, isMultipleRecord bool, isEncrypted bool, t *testing.T) {
	// Initialize collecting process
	messages := make([]*entities.Message, 0)
	cpInput := collector.CollectorInput{
		Address:       address.String(),
		Protocol:      address.Network(),
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   isEncrypted,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	if isEncrypted {
		if address.Network() == "tcp" {
			cpInput.CACert = []byte(FakeCACert)
			cpInput.ServerCert = []byte(FakeCert)
			cpInput.ServerKey = []byte(FakeKey)
		} else if address.Network() == "udp" {
			cpInput.ServerCert = []byte(FakeCert2)
			cpInput.ServerKey = []byte(FakeKey2)
		}
	}
	cp, _ := collector.InitCollectingProcess(cpInput)
	// Start collecting process
	go cp.Start()
	go func() { // Start exporting process in go routine
		waitForCollectorReady(t, cp)
		epInput := exporter.ExporterInput{
			CollectorAddress:    cp.GetAddress().String(),
			CollectorProtocol:   cp.GetAddress().Network(),
			ObservationDomainID: 1,
			TempRefTimeout:      0,
			PathMTU:             0,
			IsEncrypted:         isEncrypted,
			CACert:              nil,
		}
		if isEncrypted {
			if address.Network() == "tcp" { // use TLS
				epInput.CACert = []byte(FakeCACert)
				epInput.ClientCert = []byte(FakeClientCert)
				epInput.ClientKey = []byte(FakeClientKey)
			} else if address.Network() == "udp" { // use DTLS
				epInput.CACert = []byte(FakeCert2)
			}
		}
		export, err := exporter.InitExportingProcess(epInput)
		if err != nil {
			t.Fatalf("Got error when connecting to %s", cp.GetAddress().String())
		}
		templateID := export.NewTemplateID()
		templateSet := createTemplateSet(templateID, isIPv6)
		// Send template record
		_, err = export.SendSet(templateSet)
		if err != nil {
			t.Fatalf("Got error when sending record: %v", err)
		}
		dataSet := createDataSet(templateID, isSrcNode, isIPv6, isMultipleRecord)
		// Send data set
		_, err = export.SendSet(dataSet)
		if err != nil {
			t.Fatalf("Got error when sending record: %v", err)
		}
		export.CloseConnToCollector() // Close exporting process
	}()

	for message := range cp.GetMsgChan() {
		messages = append(messages, message)
		if len(messages) == 2 {
			cp.CloseMsgChan()
		}
	}
	cp.Stop() // Close collecting process
	templateMsg := messages[0]
	assert.Equal(t, uint16(10), templateMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), templateMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	templateSet := templateMsg.GetSet()
	templateElements := templateSet.GetRecords()[0].GetOrderedElementList()
	if !isIPv6 {
		assert.Equal(t, len(templateElements), len(commonFields)+len(ianaIPv4Fields)+len(antreaCommonFields)+len(antreaIPv4)+len(reverseFields))
	} else {
		assert.Equal(t, len(templateElements), len(commonFields)+len(ianaIPv6Fields)+len(antreaCommonFields)+len(antreaIPv6)+len(reverseFields))
	}
	assert.Equal(t, uint32(0), templateElements[0].Element.EnterpriseId, "Template record is not stored correctly.")
	if !isIPv6 {
		assert.Equal(t, "sourceIPv4Address", templateElements[0].Element.Name, "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv4Address", templateElements[1].Element.Name, "Template record is not stored correctly.")
	} else {
		assert.Equal(t, "sourceIPv6Address", templateElements[0].Element.Name, "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv6Address", templateElements[1].Element.Name, "Template record is not stored correctly.")
	}
	if !isIPv6 {
		assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[len(commonFields)+len(ianaIPv4Fields)+len(antreaCommonFields)+len(antreaIPv4)+1].Element.EnterpriseId, "Template record is not stored correctly.")
		assert.Equal(t, registry.AntreaEnterpriseID, templateElements[len(commonFields)+len(ianaIPv4Fields)+1].Element.EnterpriseId, "Template record is not stored correctly.")
	} else {
		assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[len(commonFields)+len(ianaIPv6Fields)+len(antreaCommonFields)+len(antreaIPv6)+1].Element.EnterpriseId, "Template record is not stored correctly.")
		assert.Equal(t, registry.AntreaEnterpriseID, templateElements[len(commonFields)+len(ianaIPv6Fields)+1].Element.EnterpriseId, "Template record is not stored correctly.")
	}
	dataMsg := messages[1]
	assert.Equal(t, uint16(10), dataMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), dataMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	dataSet := dataMsg.GetSet()
	record := dataSet.GetRecords()[0]
	matchDataRecordElements(t, record, isSrcNode, isIPv6)
	if isMultipleRecord {
		record = dataSet.GetRecords()[1]
		matchDataRecordElements(t, record, isSrcNode, isIPv6)
	}
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

func matchDataRecordElements(t *testing.T, record entities.Record, isSrcNode, isIPv6 bool) {
	testRec := getTestRecord(isSrcNode, isIPv6)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "sourceIPv4Address", "sourceIPv6Address":
			assert.Equal(t, testRec.srcIP, element.Value)
		case "destinationIPv4Address", "destinationIPv6Address":
			assert.Equal(t, testRec.dstIP, element.Value)
		case "sourceTransportPort":
			assert.Equal(t, testRec.srcPort, element.Value)
		case "destinationTransportPort":
			assert.Equal(t, testRec.dstPort, element.Value)
		case "protocolIdentifier":
			assert.Equal(t, testRec.proto, element.Value)
		case "packetTotalCount":
			assert.Equal(t, testRec.pktCount, element.Value)
		case "packetDeltaCount":
			assert.Equal(t, testRec.pktDelta, element.Value)
		case "flowEndSeconds":
			assert.Equal(t, testRec.flowEnd, element.Value)
		case "flowEndReason":
			assert.Equal(t, testRec.flowEndReason, element.Value)
		}
	}
	for _, name := range antreaCommonFields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "destinationClusterIPv4", "destinationClusterIPv6":
			assert.Equal(t, testRec.dstClusterIP, element.Value)
		case "sourcePodName":
			assert.Equal(t, testRec.srcPod, element.Value)
		case "destinationPodName":
			assert.Equal(t, testRec.dstPod, element.Value)
		case "destinationServicePort":
			assert.Equal(t, testRec.dstSvcPort, element.Value)
		case "flowType":
			assert.Equal(t, testRec.flowType, element.Value)
		case "tcpState":
			assert.Equal(t, testRec.tcpState, element.Value)
		}
	}
	for _, name := range reverseFields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "reversePacketTotalCount":
			assert.Equal(t, testRec.revPktCount, element.Value)
		case "reversePacketDeltaCount":
			assert.Equal(t, testRec.revPktDelta, element.Value)
		}
	}
}

func getDataRecordElements(isSrcNode, isIPv6 bool) []*entities.InfoElementWithValue {
	testRec := getTestRecord(isSrcNode, isIPv6)
	elements := make([]*entities.InfoElementWithValue, 0)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie *entities.InfoElementWithValue
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
		var ie *entities.InfoElementWithValue
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
		var ie *entities.InfoElementWithValue
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

func createTemplateSet(templateID uint16, isIPv6 bool) entities.Set {
	templateSet := entities.NewSet(false)
	templateSet.PrepareSet(entities.Template, templateID)
	elements := make([]*entities.InfoElementWithValue, 0)
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
