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
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func init() {
	// Load the global registry
	registry.LoadRegistry()
}

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
	// Start exporting process
	waitForCollectorReady(t, cp)
	epInput := exporter.ExporterInput{
		CollectorAddress:    cp.GetAddress().String(),
		CollectorProtocol:   cp.GetAddress().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		PathMTU:             0,
		IsEncrypted:         isEncrypted,
		CACert:              nil,
		CheckConnInterval:   time.Millisecond,
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
	set := dataSet

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
	templateSet = templateMsg.GetSet()
	templateElements := templateSet.GetRecords()[0].GetOrderedElementList()
	if !isIPv6 {
		assert.Equal(t, len(templateElements), len(commonFields)+len(ianaIPv4Fields)+len(antreaCommonFields)+len(antreaIPv4)+len(reverseFields))
	} else {
		assert.Equal(t, len(templateElements), len(commonFields)+len(ianaIPv6Fields)+len(antreaCommonFields)+len(antreaIPv6)+len(reverseFields))
	}
	assert.Equal(t, uint32(0), templateElements[0].GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
	if !isIPv6 {
		assert.Equal(t, "sourceIPv4Address", templateElements[0].GetInfoElement().Name, "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv4Address", templateElements[1].GetInfoElement().Name, "Template record is not stored correctly.")
	} else {
		assert.Equal(t, "sourceIPv6Address", templateElements[0].GetInfoElement().Name, "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv6Address", templateElements[1].GetInfoElement().Name, "Template record is not stored correctly.")
	}
	if !isIPv6 {
		assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[len(commonFields)+len(ianaIPv4Fields)+len(antreaCommonFields)+len(antreaIPv4)+1].GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
		assert.Equal(t, registry.AntreaEnterpriseID, templateElements[len(commonFields)+len(ianaIPv4Fields)+1].GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
	} else {
		assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[len(commonFields)+len(ianaIPv6Fields)+len(antreaCommonFields)+len(antreaIPv6)+1].GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
		assert.Equal(t, registry.AntreaEnterpriseID, templateElements[len(commonFields)+len(ianaIPv6Fields)+1].GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
	}
	dataMsg := messages[1]
	assert.Equal(t, uint16(10), dataMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), dataMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	dataSet = dataMsg.GetSet()
	record := dataSet.GetRecords()[0]
	matchDataRecordElements(t, record, isSrcNode, isIPv6)
	if isMultipleRecord {
		record = dataSet.GetRecords()[1]
		matchDataRecordElements(t, record, isSrcNode, isIPv6)
	}
	checkError := func() (bool, error) {
		_, err = export.SendSet(set)
		if err != nil {
			return true, nil
		} else {
			return false, nil
		}
	}
	if err = wait.Poll(time.Millisecond, 10*time.Millisecond, checkError); err != nil {
		t.Errorf("Collector process does not close correctly.")
	}
}

func matchDataRecordElements(t *testing.T, record entities.Record, isSrcNode, isIPv6 bool) {
	testRec := getTestRecord(isSrcNode, isIPv6)
	ianaFields := ianaIPv4Fields
	if isIPv6 {
		ianaFields = ianaIPv6Fields
	}
	ianaFields = append(ianaFields, commonFields...)
	for _, name := range ianaFields {
		element, _, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "sourceIPv4Address", "sourceIPv6Address":
			val, _ := element.GetIPAddressValue()
			assert.Equal(t, testRec.srcIP, val)
		case "destinationIPv4Address", "destinationIPv6Address":
			val, _ := element.GetIPAddressValue()
			assert.Equal(t, testRec.dstIP, val)
		case "sourceTransportPort":
			val, _ := element.GetUnsigned16Value()
			assert.Equal(t, testRec.srcPort, val)
		case "destinationTransportPort":
			val, _ := element.GetUnsigned16Value()
			assert.Equal(t, testRec.dstPort, val)
		case "protocolIdentifier":
			val, _ := element.GetUnsigned8Value()
			assert.Equal(t, testRec.proto, val)
		case "packetTotalCount":
			val, _ := element.GetUnsigned64Value()
			assert.Equal(t, testRec.pktCount, val)
		case "packetDeltaCount":
			val, _ := element.GetUnsigned64Value()
			assert.Equal(t, testRec.pktDelta, val)
		case "flowEndSeconds":
			val, _ := element.GetUnsigned32Value()
			assert.Equal(t, testRec.flowEnd, val)
		case "flowEndReason":
			val, _ := element.GetUnsigned8Value()
			assert.Equal(t, testRec.flowEndReason, val)
		}
	}
	for _, name := range antreaCommonFields {
		element, _, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "destinationClusterIPv4", "destinationClusterIPv6":
			val, _ := element.GetIPAddressValue()
			assert.Equal(t, testRec.dstClusterIP, val)
		case "sourcePodName":
			val, _ := element.GetStringValue()
			assert.Equal(t, testRec.srcPod, val)
		case "destinationPodName":
			val, _ := element.GetStringValue()
			assert.Equal(t, testRec.dstPod, val)
		case "destinationServicePort":
			val, _ := element.GetUnsigned16Value()
			assert.Equal(t, testRec.dstSvcPort, val)
		case "flowType":
			val, _ := element.GetUnsigned8Value()
			assert.Equal(t, testRec.flowType, val)
		case "tcpState":
			val, _ := element.GetStringValue()
			assert.Equal(t, testRec.tcpState, val)
		}
	}
	for _, name := range reverseFields {
		element, _, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "reversePacketTotalCount":
			val, _ := element.GetUnsigned64Value()
			assert.Equal(t, testRec.revPktCount, val)
		case "reversePacketDeltaCount":
			val, _ := element.GetUnsigned64Value()
			assert.Equal(t, testRec.revPktDelta, val)
		}
	}
}
