package intermediate

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

var fields = []string{
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

func createMsgForSrc(isIPv6 bool, isIntraNode bool) *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	svcPort := new(bytes.Buffer)
	srcPod := new(bytes.Buffer)
	dstPod := new(bytes.Buffer)
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
		srcAddr := new(bytes.Buffer)
		dstAddr := new(bytes.Buffer)
		svcAddr := new(bytes.Buffer)
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("10.0.0.1").To4())
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("10.0.0.2").To4())
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("192.168.0.1").To4())
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv4", 106, 18, 55829, 4), svcAddr)
	} else {
		srcAddr := new(bytes.Buffer)
		dstAddr := new(bytes.Buffer)
		svcAddr := new(bytes.Buffer)
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:BBBB:63::AAAA"))
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv6Address", 8, 19, 0, 16), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv6Address", 12, 19, 0, 16), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv6", 106, 19, 55829, 16), svcAddr)
	}
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)

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

func createMsgForDst(isIPv6 bool, isIntraNode bool) *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	svcPort := new(bytes.Buffer)
	srcPod := new(bytes.Buffer)
	dstPod := new(bytes.Buffer)
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
		srcAddr := new(bytes.Buffer)
		dstAddr := new(bytes.Buffer)
		svcAddr := new(bytes.Buffer)
		util.Encode(srcAddr, binary.BigEndian, net.ParseIP("10.0.0.1").To4())
		util.Encode(dstAddr, binary.BigEndian, net.ParseIP("10.0.0.2").To4())
		util.Encode(svcAddr, binary.BigEndian, net.ParseIP("0.0.0.0").To4())
		ie1 = entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), srcAddr)
		ie2 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), dstAddr)
		ie8 = entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIPv4", 106, 18, 55829, 4), svcAddr)
	} else {
		srcAddr := new(bytes.Buffer)
		dstAddr := new(bytes.Buffer)
		svcAddr := new(bytes.Buffer)
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
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)

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
	message = createMsgForSrc(false, false)
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
	message = createMsgForSrc(true, false)
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
	dataMsg := createMsgForSrc(false, false)
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
	message = createMsgForSrc(false, false)
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

func TestAggregateRecordsForInterNodeFlow(t *testing.T) {
	registry.LoadRegistry()
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	// Test IPv4 fields.
	record1 := createMsgForSrc(false, false).GetSet().GetRecords()[0]
	record2 := createMsgForDst(false, false).GetSet().GetRecords()[0]
	flowKey1, _ := getFlowKeyFromRecord(record1)
	flowKey2, _ := getFlowKeyFromRecord(record2)
	assert.Equalf(t, *flowKey1, *flowKey2, "flow keys should be equal.")
	// Test the scenario, where record1 is added first and then record2
	aggregationProcess.aggregateRecord(flowKey1, record1)
	aggregationProcess.aggregateRecord(flowKey2, record2)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
	// Test the scenario, where record2 is added first and then record1
	aggregationProcess.DeleteFlowKeyFromMap(*flowKey1)
	record1 = createMsgForSrc(false, false).GetSet().GetRecords()[0]
	record2 = createMsgForDst(false, false).GetSet().GetRecords()[0]
	aggregationProcess.aggregateRecord(flowKey2, record2)
	aggregationProcess.aggregateRecord(flowKey1, record1)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
	aggregationProcess.DeleteFlowKeyFromMap(*flowKey1)

	// Test IPv6 fields.
	record1 = createMsgForSrc(true, false).GetSet().GetRecords()[0]
	record2 = createMsgForDst(true, false).GetSet().GetRecords()[0]
	flowKey1, _ = getFlowKeyFromRecord(record1)
	flowKey2, _ = getFlowKeyFromRecord(record2)
	assert.Equalf(t, *flowKey1, *flowKey2, "flow keys should be equal.")
	// Test the scenario, where record1 is added first and then record2
	aggregationProcess.aggregateRecord(flowKey1, record1)
	aggregationProcess.aggregateRecord(flowKey2, record2)
	// We expect both IPv4 and IPv6 records to be there.
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv6")
		assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xbb, 0xbb, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xaa, 0xaa}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
	// Test the scenario, where record2 is added first and then record1.
	aggregationProcess.DeleteFlowKeyFromMap(*flowKey1)
	record1 = createMsgForSrc(true, false).GetSet().GetRecords()[0]
	record2 = createMsgForDst(true, false).GetSet().GetRecords()[0]
	aggregationProcess.aggregateRecord(flowKey2, record2)
	aggregationProcess.aggregateRecord(flowKey1, record1)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv6")
		assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xbb, 0xbb, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xaa, 0xaa}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
}

func TestAggregateRecordsForIntraNodeFlow(t *testing.T) {
	registry.LoadRegistry()
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	// Test IPv4 fields.
	record1 := createMsgForSrc(false, true).GetSet().GetRecords()[0]
	flowKey1, _ := getFlowKeyFromRecord(record1)
	// Test the scenario, where record1 is added first and then record2
	aggregationProcess.aggregateRecord(flowKey1, record1)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv4")
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
	aggregationProcess.DeleteFlowKeyFromMap(*flowKey1)

	// Test IPv6 fields.
	record1 = createMsgForSrc(true, true).GetSet().GetRecords()[0]
	flowKey1, _ = getFlowKeyFromRecord(record1)
	// Test the scenario, where record1 is added first and then record2
	aggregationProcess.aggregateRecord(flowKey1, record1)
	// We expect both IPv4 and IPv6 records to be there.
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, aggRecord := range aggregationProcess.flowKeyRecordMap {
		ieWithValue, _ := aggRecord.Record.GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationClusterIPv6")
		assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xbb, 0xbb, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xaa, 0xaa}, ieWithValue.Value)
		ieWithValue, _ = aggRecord.Record.GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
}

func TestDeleteTupleFromMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	input := AggregationInput{
		MessageChan:     messageChan,
		WorkerNum:       2,
		CorrelateFields: fields,
	}
	aggregationProcess, _ := InitAggregationProcess(input)
	message := createMsgForSrc(false, false)
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
