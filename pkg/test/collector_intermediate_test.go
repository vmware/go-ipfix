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
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/intermediate"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	flowKeyRecordMap = make(map[intermediate.FlowKey]intermediate.AggregationFlowRecord)
	flowKey1         = intermediate.FlowKey{SourceAddress: "10.0.0.1", DestinationAddress: "10.0.0.2", Protocol: 6, SourcePort: 1234, DestinationPort: 5678}
	flowKey2         = intermediate.FlowKey{SourceAddress: "2001:0:3238:dfe1:63::fefb", DestinationAddress: "2001:0:3238:dfe1:63::fefc", Protocol: 6, SourcePort: 1234, DestinationPort: 5678}
	correlatefields  = []string{
		"sourcePodName",
		"sourcePodNamespace",
		"sourceNodeName",
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
		"destinationClusterIPv4",
		"destinationClusterIPv6",
		"destinationServicePort",
	}
	nonStatsElementList = []string{
		"flowEndSeconds",
		"flowEndReason",
		"tcpState",
	}
	statsElementList = []string{
		"packetTotalCount",
		"packetDeltaCount",
		"reversePacketTotalCount",
		"reversePacketDeltaCount",
		"octetTotalCount",
		"reverseOctetTotalCount",
	}
	antreaSourceStatsElementList = []string{
		"packetTotalCountFromSourceNode",
		"packetDeltaCountFromSourceNode",
		"reversePacketTotalCountFromSourceNode",
		"reversePacketDeltaCountFromSourceNode",
		"octetTotalCountFromSourceNode",
		"reverseOctetTotalCountFromSourceNode",
	}
	antreaDestinationStatsElementList = []string{
		"packetTotalCountFromDestinationNode",
		"packetDeltaCountFromDestinationNode",
		"reversePacketTotalCountFromDestinationNode",
		"reversePacketDeltaCountFromDestinationNode",
		"octetTotalCountFromDestinationNode",
		"reverseOctetTotalCountFromDestinationNode",
	}
	antreaFlowEndSecondsElementList = []string{
		"flowEndSecondsFromSourceNode",
		"flowEndSecondsFromDestinationNode",
	}
	antreaThroughputElements = []string{
		"throughput",
		"reverseThroughput",
	}
	antreaSourceThroughputElements = []string{
		"throughputFromSourceNode",
		"reverseThroughputFromSourceNode",
	}
	antreaDestinationThroughputElements = []string{
		"throughputFromDestinationNode",
		"reverseThroughputFromDestinationNode",
	}
	aggregationWorkerNum = 2
)

func TestCollectorToIntermediateIPv4(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testCollectorToIntermediate(t, address, false)
}

func TestCollectorToIntermediateIPv6(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "[::1]:0")
	if err != nil {
		t.Error(err)
	}
	testCollectorToIntermediate(t, address, true)
}

func testCollectorToIntermediate(t *testing.T, address net.Addr, isIPv6 bool) {
	aggregatedFields := &intermediate.AggregationElements{
		NonStatsElements:                   nonStatsElementList,
		StatsElements:                      statsElementList,
		AggregatedSourceStatsElements:      antreaSourceStatsElementList,
		AggregatedDestinationStatsElements: antreaDestinationStatsElementList,
		AntreaFlowEndSecondsElements:       antreaFlowEndSecondsElementList,
		ThroughputElements:                 antreaThroughputElements,
		SourceThroughputElements:           antreaSourceThroughputElements,
		DestinationThroughputElements:      antreaDestinationThroughputElements,
	}
	// Initialize aggregation process and collecting process
	cpInput := collector.CollectorInput{
		Address:       address.String(),
		Protocol:      address.Network(),
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, _ := collector.InitCollectingProcess(cpInput)

	apInput := intermediate.AggregationInput{
		MessageChan:       cp.GetMsgChan(),
		WorkerNum:         aggregationWorkerNum,
		CorrelateFields:   correlatefields,
		AggregateElements: aggregatedFields,
	}
	ap, _ := intermediate.InitAggregationProcess(apInput)
	go cp.Start()
	waitForCollectorReady(t, cp)
	go ap.Start()
	func() {
		collectorAddr, _ := net.ResolveTCPAddr("tcp", cp.GetAddress().String())
		conn, err := net.DialTCP("tcp", nil, collectorAddr)
		if err != nil {
			t.Errorf("TCP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		if isIPv6 {
			conn.Write(templatePacketIPv6)
			conn.Write(dataPacket1IPv6)
			conn.Write(dataPacket2IPv6)
		} else {
			conn.Write(templatePacketIPv4)
			conn.Write(dataPacket1IPv4)
			conn.Write(dataPacket2IPv4)
		}
	}()
	if isIPv6 {
		waitForAggregationToFinish(t, ap, flowKey2)
	} else {
		waitForAggregationToFinish(t, ap, flowKey1)
	}
	cp.Stop()
	ap.Stop()

	var record entities.Record
	if isIPv6 {
		assert.NotNil(t, flowKeyRecordMap[flowKey2])
		record = flowKeyRecordMap[flowKey2].Record
	} else {
		assert.NotNil(t, flowKeyRecordMap[flowKey1])
		record = flowKeyRecordMap[flowKey1].Record
	}
	assert.Equal(t, 40, len(record.GetOrderedElementList()))
	for _, element := range record.GetOrderedElementList() {
		infoElem := element.GetInfoElement()
		switch infoElem.Name {
		case "sourcePodName":
			assert.Equal(t, "pod1", element.GetStringValue())
		case "destinationPodName":
			assert.Equal(t, "pod2", element.GetStringValue())
		case "flowStartSeconds":
			assert.Equal(t, uint32(1257893000), element.GetUnsigned32Value(), "element %s does not have the correct value", element.GetName())
		case "flowEndSeconds", "flowEndSecondsFromDestinationNode":
			assert.Equalf(t, uint32(1257896000), element.GetUnsigned32Value(), "element %s does not have the correct value", element.GetName())
		case "flowEndSecondsFromSourceNode":
			assert.Equalf(t, uint32(1257894000), element.GetUnsigned32Value(), "element %s does not have the correct value", element.GetName())
		case "flowEndReason":
			assert.Equal(t, registry.ActiveTimeoutReason, element.GetUnsigned8Value())
		case "tcpState":
			assert.Equal(t, "ESTABLISHED", element.GetStringValue())
		case "packetDeltaCount":
			assert.Equal(t, uint64(500), element.GetUnsigned64Value())
		case "packetTotalCount":
			assert.Equal(t, uint64(1000), element.GetUnsigned64Value())
		case "destinationClusterIPv4":
			assert.Equal(t, net.IP{10, 0, 0, 3}, element.GetIPAddressValue())
		case "destinationClusterIPv6":
			assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xbb, 0xbb, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xaa, 0xaa}, element.GetIPAddressValue())
		case "destinationServicePort":
			assert.Equal(t, uint16(4739), element.GetUnsigned16Value())
		case "reversePacketDeltaCount":
			assert.Equal(t, uint64(200), element.GetUnsigned64Value())
		case "reversePacketTotalCount":
			assert.Equal(t, uint64(400), element.GetUnsigned64Value())
		case "packetTotalCountFromSourceNode":
			assert.Equal(t, uint64(800), element.GetUnsigned64Value())
		case "packetDeltaCountFromSourceNode":
			assert.Equal(t, uint64(500), element.GetUnsigned64Value())
		case "packetTotalCountFromDestinationNode":
			assert.Equal(t, uint64(1000), element.GetUnsigned64Value())
		case "packetDeltaCountFromDestinationNode":
			assert.Equal(t, uint64(500), element.GetUnsigned64Value())
		case "reversePacketTotalCountFromSourceNode":
			assert.Equal(t, uint64(300), element.GetUnsigned64Value())
		case "reversePacketDeltaCountFromSourceNode":
			assert.Equal(t, uint64(150), element.GetUnsigned64Value())
		case "reversePacketTotalCountFromDestinationNode":
			assert.Equal(t, uint64(400), element.GetUnsigned64Value())
		case "reversePacketDeltaCountFromDestinationNode":
			assert.Equal(t, uint64(200), element.GetUnsigned64Value())
		case "octetTotalCount":
			assert.Equal(t, uint64(1000000), element.GetUnsigned64Value())
		case "reverseOctetTotalCount":
			assert.Equal(t, uint64(400000), element.GetUnsigned64Value())
		case "throughput":
			assert.Equal(t, uint64(1000000*8/3000), element.GetUnsigned64Value())
		case "reverseThroughput":
			assert.Equal(t, uint64(400000*8/3000), element.GetUnsigned64Value())
		case "throughputFromSourceNode":
			assert.Equal(t, uint64(800000*8/1000), element.GetUnsigned64Value())
		case "throughputFromDestinationNode":
			assert.Equal(t, uint64(1000000*8/3000), element.GetUnsigned64Value())
		case "reverseThroughputFromSourceNode":
			assert.Equal(t, uint64(300000*8/1000), element.GetUnsigned64Value())
		case "reverseThroughputFromDestinationNode":
			assert.Equal(t, uint64(400000*8/3000), element.GetUnsigned64Value())
		}
	}
}

func copyFlowKeyRecordMap(key intermediate.FlowKey, aggregationFlowRecord *intermediate.AggregationFlowRecord) error {
	flowKeyRecordMap[key] = *aggregationFlowRecord
	return nil
}

func waitForCollectorReady(t *testing.T, cp *collector.CollectingProcess) {
	checkConn := func() (bool, error) {
		if strings.Split(cp.GetAddress().String(), ":")[1] == "0" {
			return false, fmt.Errorf("random port is not resolved")
		}
		conn, err := net.Dial(cp.GetAddress().Network(), cp.GetAddress().String())
		if err != nil {
			return false, err
		}
		conn.Close()
		return true, nil
	}
	if err := wait.Poll(100*time.Millisecond, 500*time.Millisecond, checkConn); err != nil {
		t.Errorf("Cannot establish connection to %s", cp.GetAddress().String())
	}
}

func waitForAggregationToFinish(t *testing.T, ap *intermediate.AggregationProcess, key intermediate.FlowKey) {
	checkConn := func() (bool, error) {
		ap.ForAllRecordsDo(copyFlowKeyRecordMap)
		if len(flowKeyRecordMap) > 0 {
			ie1, _, _ := flowKeyRecordMap[key].Record.GetInfoElementWithValue("sourcePodName")
			ie2, _, _ := flowKeyRecordMap[key].Record.GetInfoElementWithValue("destinationPodName")
			if ie1.GetStringValue() == "pod1" && ie2.GetStringValue() == "pod2" {
				return true, nil
			} else {
				return false, nil
			}
		} else {
			return false, fmt.Errorf("aggregation process does not process and store data correctly")
		}
	}
	if err := wait.Poll(100*time.Millisecond, 500*time.Millisecond, checkConn); err != nil {
		t.Error(err)
	}
}
