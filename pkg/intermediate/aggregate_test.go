package intermediate

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

var (
	fields = []string{
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
	}
	statsElementList = []string{
		"packetTotalCount",
		"packetDeltaCount",
		"reversePacketTotalCount",
		"reversePacketDeltaCount",
	}
	antreaSourceStatsElementList = []string{
		"packetTotalCountFromSourceNode",
		"packetDeltaCountFromSourceNode",
		"reversePacketTotalCountFromSourceNode",
		"reversePacketDeltaCountFromSourceNode",
	}
	antreaDestinationStatsElementList = []string{
		"packetTotalCountFromDestinationNode",
		"packetDeltaCountFromDestinationNode",
		"reversePacketTotalCountFromDestinationNode",
		"reversePacketDeltaCountFromDestinationNode",
	}
)

func init() {
	registry.LoadRegistry()
}

func createMsgwithTemplateSet(isIPv6 bool) *entities.Message {
	set := entities.NewSet(entities.Template, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), nil)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), nil)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), nil)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), nil)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), nil)
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), nil)
	var ie1, ie2, ie8 *entities.InfoElementWithValue
	if !isIPv6 {
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv4", 106, 18, 55829, 4), nil)
	} else {
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), nil)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), nil)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv6", 106, 19, 55829, 16), nil)
	}
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(40)
	message.SetSequenceNum(1)
	message.SetObsDomainID(5678)
	message.SetExportTime(0)
	message.SetExportAddress("127.0.0.1")
	message.AddSet(set)

	return message
}

// TODO:Cleanup this function using a loop, to make it easy to add elements for testing.
func createDataMsgForSrc(t *testing.T, isIPv6 bool, isIntraNode bool, isUpdatedRecord bool) *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	svcPort := new(bytes.Buffer)
	srcPod := new(bytes.Buffer)
	dstPod := new(bytes.Buffer)
	srcAddr := new(bytes.Buffer)
	dstAddr := new(bytes.Buffer)
	svcAddr := new(bytes.Buffer)
	flowEndTime := new(bytes.Buffer)

	util.Encode(srcPort, binary.BigEndian, uint16(1234))
	util.Encode(dstPort, binary.BigEndian, uint16(5678))
	util.Encode(proto, binary.BigEndian, uint8(6))
	util.Encode(svcPort, binary.BigEndian, uint16(4739))
	srcPod.WriteString("pod1")
	if !isIntraNode {
		dstPod.WriteString("")
	} else {
		dstPod.WriteString("pod2")
	}
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), srcPod)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), dstPod)
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), svcPort)
	var ie1, ie2, ie8 *entities.InfoElementWithValue
	if !isIPv6 {
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("10.0.0.1").To4())
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("10.0.0.2").To4())
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("192.168.0.1").To4())
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv4", 106, 18, 55829, 4), svcAddr)
	} else {
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:BBBB:63::AAAA"))
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv6", 106, 19, 55829, 16), svcAddr)
	}

	if !isUpdatedRecord {
		util.Encode(flowEndTime, binary.BigEndian, uint32(1))
	} else {
		util.Encode(flowEndTime, binary.BigEndian, uint32(10))
	}
	element, _ := registry.GetInfoElement("flowEndSeconds", registry.IANAEnterpriseID)
	ie10 := entities.NewInfoElementWithValue(element, flowEndTime)

	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9, ie10)
	// Add all elements in statsElements.
	for _, element := range statsElementList {
		var e *entities.InfoElement
		if !strings.Contains(element, "reverse") {
			e, _ = registry.GetInfoElement(element, registry.IANAEnterpriseID)
		} else {
			e, _ = registry.GetInfoElement(element, registry.IANAReversedEnterpriseID)
		}
		ieWithValue := entities.NewInfoElementWithValue(e, nil)
		value := new(bytes.Buffer)
		switch element {
		case "packetTotalCount", "reversePacketTotalCount":
			if !isUpdatedRecord {
				util.Encode(value, binary.BigEndian, uint64(500))
			} else {
				util.Encode(value, binary.BigEndian, uint64(1000))
			}
		case "packetDeltaCount", "reversePacketDeltaCount":
			if !isUpdatedRecord {
				util.Encode(value, binary.BigEndian, uint64(0))
			} else {
				util.Encode(value, binary.BigEndian, uint64(500))
			}
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}

	err := set.AddRecord(elements, 256)
	assert.NoError(t, err)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(32)
	message.SetSequenceNum(1)
	message.SetObsDomainID(1234)
	message.SetExportTime(0)
	message.SetExportAddress("127.0.0.1")
	message.AddSet(set)

	return message
}

func createDataMsgForDst(t *testing.T, isIPv6 bool, isIntraNode bool, isUpdatedRecord bool) *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	svcPort := new(bytes.Buffer)
	srcPod := new(bytes.Buffer)
	dstPod := new(bytes.Buffer)
	srcAddr := new(bytes.Buffer)
	dstAddr := new(bytes.Buffer)
	svcAddr := new(bytes.Buffer)
	flowEndTime := new(bytes.Buffer)

	util.Encode(srcPort, binary.BigEndian, uint16(1234))
	util.Encode(dstPort, binary.BigEndian, uint16(5678))
	util.Encode(proto, binary.BigEndian, uint8(6))
	if !isIntraNode {
		util.Encode(svcPort, binary.BigEndian, uint16(0))
		srcPod.WriteString("")
	} else {
		util.Encode(svcPort, binary.BigEndian, uint16(4739))
		srcPod.WriteString("pod1")
	}
	dstPod.WriteString("pod2")
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), srcPod)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), dstPod)
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), svcPort)
	var ie1, ie2, ie8 *entities.InfoElementWithValue
	if !isIPv6 {
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("10.0.0.1").To4())
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("10.0.0.2").To4())
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("0.0.0.0").To4())
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv4", 106, 18, 55829, 4), svcAddr)
	} else {
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		if !isIntraNode {
			util.Encode(svcAddr, binary.BigEndian, net.ParseIP("::0"))
		} else {
			util.Encode(svcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:BBBB:63::AAAA"))
		}
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv6", 106, 19, 55829, 16), svcAddr)
	}

	if !isUpdatedRecord {
		util.Encode(flowEndTime, binary.BigEndian, uint32(1))
	} else {
		util.Encode(flowEndTime, binary.BigEndian, uint32(20))
	}
	element, _ := registry.GetInfoElement("flowEndSeconds", registry.IANAEnterpriseID)
	ie10 := entities.NewInfoElementWithValue(element, flowEndTime)

	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9, ie10)
	// Add all elements in statsElements.
	for _, element := range statsElementList {
		var e *entities.InfoElement
		if !strings.Contains(element, "reverse") {
			e, _ = registry.GetInfoElement(element, registry.IANAEnterpriseID)
		} else {
			e, _ = registry.GetInfoElement(element, registry.IANAReversedEnterpriseID)
		}
		ieWithValue := entities.NewInfoElementWithValue(e, nil)
		value := new(bytes.Buffer)
		switch element {
		case "packetTotalCount", "reversePacketTotalCount":
			if !isUpdatedRecord {
				util.Encode(value, binary.BigEndian, uint64(502))
			} else {
				util.Encode(value, binary.BigEndian, uint64(1005))
			}
		case "packetDeltaCount", "reversePacketDeltaCount":
			if !isUpdatedRecord {
				util.Encode(value, binary.BigEndian, uint64(0))
			} else {
				util.Encode(value, binary.BigEndian, uint64(503))
			}
		}
		ieWithValue.Value = value
		elements = append(elements, ieWithValue)
	}
	err := set.AddRecord(elements, 256)
	assert.NoError(t, err)

	message := entities.NewMessage(true)
	message.SetVersion(10)
	message.SetMessageLen(32)
	message.SetSequenceNum(1)
	message.SetObsDomainID(1234)
	message.SetExportTime(0)
	message.SetExportAddress("127.0.0.1")
	message.AddSet(set)

	return message
}

func TestInitAggregationProcess(t *testing.T) {
	input := AggregationInput{
		MessageChan:     nil,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, err := InitAggregationProcess(input)
	assert.NotNil(t, err)
	assert.Nil(t, aggregationProcess)
	messageChan := make(chan *entities.Message)
	input.MessageChan = messageChan
	aggregationProcess, err = InitAggregationProcess(input)
	assert.Nil(t, err)
	assert.Equal(t, 2, aggregationProcess.workerNum)
}

func TestGetTupleRecordMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	assert.Equal(t, aggregationProcess.flowKeyRecordMap, aggregationProcess.flowKeyRecordMap)
}

func TestAggregateMsgByFlowKey(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	// Template records with IPv4 fields should be ignored
	message := createMsgwithTemplateSet(false)
	err := aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
	// Data records should be processed and stored with corresponding flow key
	message = createDataMsgForSrc(t, false, false, false)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.NotZero(t, len(aggregationProcess.flowKeyRecordMap))
	flowKey := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	aggRecord := aggregationProcess.flowKeyRecordMap[flowKey]
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	ieWithValue, exist := aggRecord.Record.GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0xa, 0x0, 0x0, 0x1}, ieWithValue.Value)
	assert.Equal(t, message.GetSet().GetRecords()[0], aggRecord.Record)

	// Template records with IPv6 fields should be ignored
	message = createMsgwithTemplateSet(true)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	// It should have only data record with IPv4 fields that is added before.
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	// Data record with IPv6 addresses should be processed and stored correctly
	message = createDataMsgForSrc(t, true, false, false)
	err = aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(aggregationProcess.flowKeyRecordMap))
	flowKey = FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	aggRecord = aggregationProcess.flowKeyRecordMap[flowKey]
	ieWithValue, exist = aggRecord.Record.GetInfoElementWithValue("sourceIPv6Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}, ieWithValue.Value)
	assert.Equal(t, message.GetSet().GetRecords()[0], aggRecord.Record)
}

func TestAggregationProcess(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	dataMsg := createDataMsgForSrc(t, false, false, false)
	go func() {
		messageChan <- createMsgwithTemplateSet(false)
		time.Sleep(time.Second)
		messageChan <- dataMsg
		time.Sleep(time.Second)
		close(messageChan)
		aggregationProcess.Stop()
	}()
	// the Start() function is blocking until above goroutine with Stop() finishes
	// Proper usage of aggregation process is to have Start() in a goroutine with external channel
	aggregationProcess.Start()
	flowKey := FlowKey{
		"10.0.0.1", "10.0.0.2", 6, 1234, 5678,
	}
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
}

func TestAddOriginalExporterInfo(t *testing.T) {
	// Test message with template set
	message := createMsgwithTemplateSet(false)
	err := addOriginalExporterInfo(message)
	assert.NoError(t, err)
	record := message.GetSet().GetRecords()[0]
	_, exist := record.GetInfoElementWithValue("originalExporterIPv4Address")
	assert.Equal(t, true, exist)
	_, exist = record.GetInfoElementWithValue("originalObservationDomainId")
	assert.Equal(t, true, exist)
	// Test message with data set
	message = createDataMsgForSrc(t, false, false, false)
	err = addOriginalExporterInfo(message)
	assert.NoError(t, err)
	record = message.GetSet().GetRecords()[0]
	ieWithValue, exist := record.GetInfoElementWithValue("originalExporterIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0x7f, 0x0, 0x0, 0x1}, ieWithValue.Value)
	ieWithValue, exist = record.GetInfoElementWithValue("originalObservationDomainId")
	assert.Equal(t, true, exist)
	assert.Equal(t, uint32(1234), ieWithValue.Value)
}

func TestCorrelateRecordsForInterNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	ap, _ := InitAggregationProcess(input)
	// Test IPv4 fields.
	// Test the scenario, where record1 is added first and then record2.
	record1 := createDataMsgForSrc(t, false, false, false).GetSet().GetRecords()[0]
	record2 := createDataMsgForDst(t, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record1, record2, false, false)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	ap.DeleteFlowKeyFromMap(*flowKey1)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createDataMsgForSrc(t, false, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, false, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record2, record1, false, false)
	// Cleanup the flowKeyMap in aggregation process.
	ap.DeleteFlowKeyFromMap(*flowKey1)

	// Test IPv6 fields.
	// Test the scenario, where record1 is added first and then record2.
	record1 = createDataMsgForSrc(t, true, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, true, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record1, record2, true, false)
	// Cleanup the flowKeyMap in aggregation process.
	ap.DeleteFlowKeyFromMap(*flowKey1)
	// Test the scenario, where record2 is added first and then record1.
	record1 = createDataMsgForSrc(t, true, false, false).GetSet().GetRecords()[0]
	record2 = createDataMsgForDst(t, true, false, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record2, record1, true, false)
}

func TestCorrelateRecordsForIntraNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	ap, _ := InitAggregationProcess(input)
	// Test IPv4 fields.
	record1 := createDataMsgForSrc(t, false, true, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record1, nil, false, true)
	// Cleanup the flowKeyMap in aggregation process.
	flowKey1, _ := getFlowKeyFromRecord(record1)
	ap.DeleteFlowKeyFromMap(*flowKey1)
	// Test IPv6 fields.
	record1 = createDataMsgForSrc(t, true, true, false).GetSet().GetRecords()[0]
	runCorrelationAndCheckResult(t, ap, record1, nil, true, true)
}

func TestAggregateRecordsForInterNodeFlow(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggElements := &AggregationElements{
		nonStatsElements:                   nonStatsElementList,
		statsElements:                      statsElementList,
		aggregatedSourceStatsElements:      antreaSourceStatsElementList,
		aggregatedDestinationStatsElements: antreaDestinationStatsElementList,
	}
	input := AggregationInput{
		MessageChan:       messageChan,
		WorkerNum:         2,
		CorrelateFields:   fields,
		AggregateElements: aggElements,
	}
	ap, _ := InitAggregationProcess(input)

	// Test the scenario (added in order): srcRecord, dstRecord, record1_updated, record2_updated
	srcRecord := createDataMsgForSrc(t, false, false, false).GetSet().GetRecords()[0]
	dstRecord := createDataMsgForDst(t, false, false, false).GetSet().GetRecords()[0]
	latestSrcRecord := createDataMsgForSrc(t, false, false, true).GetSet().GetRecords()[0]
	latestDstRecord := createDataMsgForDst(t, false, false, true).GetSet().GetRecords()[0]
	runAggregationAndCheckResult(t, ap, srcRecord, dstRecord, latestSrcRecord, latestDstRecord, false)
}

func TestDeleteTupleFromMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	message := createDataMsgForSrc(t, false, false, false)
	flowKey1 := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	flowKey2 := FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	aggFlowRecord := AggregationFlowRecord{
		message.GetSet().GetRecords()[0],
		true,
		true,
	}
	aggregationProcess.flowKeyRecordMap[flowKey1] = aggFlowRecord
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	aggregationProcess.DeleteFlowKeyFromMap(flowKey2)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	aggregationProcess.DeleteFlowKeyFromMap(flowKey1)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
}

func runCorrelationAndCheckResult(t *testing.T, ap *AggregationProcess, record1, record2 entities.Record, isIPv6, isIntraNode bool) {
	flowKey1, _ := getFlowKeyFromRecord(record1)
	err := ap.addOrUpdateRecordInMap(flowKey1, record1)
	assert.NoError(t, err)
	if !isIntraNode {
		flowKey2, _ := getFlowKeyFromRecord(record2)
		assert.Equalf(t, *flowKey1, *flowKey2, "flow keys should be equal.")
		err = ap.addOrUpdateRecordInMap(flowKey2, record2)
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, len(ap.flowKeyRecordMap))
	aggRecord, _ := ap.flowKeyRecordMap[*flowKey1]
	ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
	assert.Equal(t, "pod1", ieWithValue.Value)
	ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
	assert.Equal(t, "pod2", ieWithValue.Value)
	if !isIPv6 {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
	} else {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv6")
		assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xbb, 0xbb, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xaa, 0xaa}, ieWithValue.Value)
	}
	ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
	assert.Equal(t, uint16(4739), ieWithValue.Value)
}

func runAggregationAndCheckResult(t *testing.T, ap *AggregationProcess, srcRecord, dstRecord, srcRecordLatest, dstRecordLatest entities.Record, isIntraNode bool) {
	flowKey, _ := getFlowKeyFromRecord(srcRecord)
	err := ap.addOrUpdateRecordInMap(flowKey, srcRecord)
	assert.NoError(t, err)
	if !isIntraNode {
		err = ap.addOrUpdateRecordInMap(flowKey, dstRecord)
		assert.NoError(t, err)
	}
	err = ap.addOrUpdateRecordInMap(flowKey, srcRecordLatest)
	assert.NoError(t, err)
	if !isIntraNode {
		err = ap.addOrUpdateRecordInMap(flowKey, dstRecordLatest)
		assert.NoError(t, err)
	}
	assert.Equal(t, 1, len(ap.flowKeyRecordMap))
	aggRecord, _ := ap.flowKeyRecordMap[*flowKey]
	ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
	assert.Equal(t, "pod1", ieWithValue.Value)
	ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
	assert.Equal(t, "pod2", ieWithValue.Value)
	ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
	assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
	ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
	assert.Equal(t, uint16(4739), ieWithValue.Value)
	for _, e := range nonStatsElementList {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue(e)
		expectedIE, _ := dstRecordLatest.GetInfoElementWithValue(e)
		assert.Equal(t, expectedIE.Value, ieWithValue.Value)
	}
	for _, e := range statsElementList {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue(e)
		latestRecord, _ := dstRecordLatest.GetInfoElementWithValue(e)
		if !strings.Contains(e, "Delta") {
			assert.Equalf(t, latestRecord.Value, ieWithValue.Value, "values should be equal for element %v", e)
		} else {
			prevRecord, _ := srcRecordLatest.GetInfoElementWithValue(e)
			assert.Equalf(t, prevRecord.Value.(uint64)+latestRecord.Value.(uint64), ieWithValue.Value, "values should be equal for element %v", e)
		}
	}
	for i, e := range antreaSourceStatsElementList {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue(e)
		latestRecord, _ := srcRecordLatest.GetInfoElementWithValue(statsElementList[i])
		assert.Equalf(t, latestRecord.Value, ieWithValue.Value, "values should be equal for element %v", e)
	}
	for i, e := range antreaDestinationStatsElementList {
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue(e)
		latestRecord, _ := dstRecordLatest.GetInfoElementWithValue(statsElementList[i])
		assert.Equalf(t, latestRecord.Value, ieWithValue.Value, "values should be equal for element %v", e)
	}
}
