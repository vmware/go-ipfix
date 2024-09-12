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

//go:build integration
// +build integration

package test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
	testcerts "github.com/vmware/go-ipfix/pkg/test/certs"
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
	messages := make([]*entities.Message, 2)
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
			cpInput.CACert = []byte(testcerts.FakeCACert)
			cpInput.ServerCert = []byte(testcerts.FakeCert)
			cpInput.ServerKey = []byte(testcerts.FakeKey)
		} else if address.Network() == "udp" {
			cpInput.ServerCert = []byte(testcerts.FakeCert2)
			cpInput.ServerKey = []byte(testcerts.FakeKey2)
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
		CheckConnInterval:   time.Millisecond,
	}
	if isEncrypted {
		tlsClientConfig := &exporter.ExporterTLSClientConfig{}
		if address.Network() == "tcp" { // use TLS
			tlsClientConfig.CAData = []byte(testcerts.FakeCACert)
			tlsClientConfig.CertData = []byte(testcerts.FakeClientCert)
			tlsClientConfig.KeyData = []byte(testcerts.FakeClientKey)
		} else if address.Network() == "udp" { // use DTLS
			tlsClientConfig.CAData = []byte(testcerts.FakeCert2)
		}
		epInput.TLSClientConfig = tlsClientConfig
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

	messageIdx := 0
	for message := range cp.GetMsgChan() {
		messages[messageIdx] = message
		messageIdx++
		if messageIdx == 2 {
			cp.CloseMsgChan()
		}
	}
	cp.Stop() // Close collecting process
	require.Equal(t, 2, messageIdx)
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
		assert.Equal(t, "sourceIPv4Address", templateElements[0].GetName(), "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv4Address", templateElements[1].GetName(), "Template record is not stored correctly.")
	} else {
		assert.Equal(t, "sourceIPv6Address", templateElements[0].GetName(), "Template record is not stored correctly.")
		assert.Equal(t, "destinationIPv6Address", templateElements[1].GetName(), "Template record is not stored correctly.")
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
	checkError := func(ctx context.Context) (bool, error) {
		_, err = export.SendSet(set)
		if err != nil {
			return true, nil
		} else {
			return false, nil
		}
	}
	if err = wait.PollUntilContextTimeout(context.Background(), time.Millisecond, 10*time.Millisecond, false, checkError); err != nil {
		t.Errorf("Collector process did not close correctly.")
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
		assert.Truef(t, exist, "element with name %s should exist in the record", name)
		switch name {
		case "sourceIPv4Address", "sourceIPv6Address":
			assert.Equal(t, testRec.srcIP, element.GetIPAddressValue())
		case "destinationIPv4Address", "destinationIPv6Address":
			assert.Equal(t, testRec.dstIP, element.GetIPAddressValue())
		case "sourceTransportPort":
			assert.Equal(t, testRec.srcPort, element.GetUnsigned16Value())
		case "destinationTransportPort":
			assert.Equal(t, testRec.dstPort, element.GetUnsigned16Value())
		case "protocolIdentifier":
			assert.Equal(t, testRec.proto, element.GetUnsigned8Value())
		case "packetTotalCount":
			assert.Equal(t, testRec.pktCount, element.GetUnsigned64Value())
		case "packetDeltaCount":
			assert.Equal(t, testRec.pktDelta, element.GetUnsigned64Value())
		case "flowStartSeconds":
			assert.Equal(t, testRec.flowStart, element.GetUnsigned32Value())
		case "flowEndSeconds":
			assert.Equal(t, testRec.flowEnd, element.GetUnsigned32Value())
		case "flowEndReason":
			assert.Equal(t, testRec.flowEndReason, element.GetUnsigned8Value())
		}
	}
	for _, name := range antreaCommonFields {
		element, _, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "destinationClusterIPv4", "destinationClusterIPv6":
			assert.Equal(t, testRec.dstClusterIP, element.GetIPAddressValue())
		case "sourcePodName":
			assert.Equal(t, testRec.srcPod, element.GetStringValue())
		case "destinationPodName":
			assert.Equal(t, testRec.dstPod, element.GetStringValue())
		case "destinationServicePort":
			assert.Equal(t, testRec.dstSvcPort, element.GetUnsigned16Value())
		case "flowType":
			assert.Equal(t, testRec.flowType, element.GetUnsigned8Value())
		case "tcpState":
			assert.Equal(t, testRec.tcpState, element.GetStringValue())
		}
	}
	for _, name := range reverseFields {
		element, _, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "reversePacketTotalCount":
			assert.Equal(t, testRec.revPktCount, element.GetUnsigned64Value())
		case "reversePacketDeltaCount":
			assert.Equal(t, testRec.revPktDelta, element.GetUnsigned64Value())
		case "reverseOctetTotalCount":
			assert.Equal(t, testRec.revBytCount, element.GetUnsigned64Value())
		}
	}
}
