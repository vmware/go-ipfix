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
	"destinationPodName",
	"destinationPodNamespace",
	"destinationNodeName",
}

func createMsgwithTemplateSet() *entities.Message {
	set := entities.NewSet(entities.Template, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), nil)
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), nil)
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), nil)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), nil)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), nil)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), nil)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), nil)
	ie8 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIP", 106, 18, 55829, 4), nil)
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), nil)
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)
	return &entities.Message{
		Version:       10,
		BufferLength:  40,
		SeqNumber:     1,
		ObsDomainID:   5678,
		ExportTime:    0,
		ExportAddress: "127.0.0.1",
		Set:           set,
	}
}

func createMsgwithDataSet1() *entities.Message {
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
	dstPod.WriteString("")
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 1}))
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 2}))
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), srcPod)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), dstPod)
	ie8 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIP", 106, 18, 55829, 4), bytes.NewBuffer([]byte{192, 168, 0, 1}))
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), svcPort)
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)
	return &entities.Message{
		Version:       10,
		BufferLength:  32,
		SeqNumber:     1,
		ObsDomainID:   uint32(1234),
		ExportTime:    0,
		ExportAddress: "127.0.0.1",
		Set:           set,
	}
}

func createMsgwithDataSet2() *entities.Message {
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
	srcPod.WriteString("")
	dstPod.WriteString("pod2")
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), bytes.NewBuffer(net.IP{10, 0, 0, 1}))
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), bytes.NewBuffer(net.IP{10, 0, 0, 2}))
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	ie6 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535), srcPod)
	ie7 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535), dstPod)
	ie8 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationClusterIP", 106, 18, 55829, 4), nil)
	ie9 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2), nil)
	elements = append(elements, ie1, ie2, ie3, ie4, ie5, ie6, ie7, ie8, ie9)
	set.AddRecord(elements, 256)
	return &entities.Message{
		Version:       10,
		BufferLength:  32,
		SeqNumber:     1,
		ObsDomainID:   uint32(1234),
		ExportTime:    0,
		ExportAddress: "127.0.0.1",
		Set:           set,
	}
}

func createMsgwithDataSetIPv6() *entities.Message {
	set := entities.NewSet(entities.Data, 257, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	srcAddr := new(bytes.Buffer)
	dstAddr := new(bytes.Buffer)
	util.Encode(srcAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFB"))
	util.Encode(dstAddr, binary.BigEndian, net.ParseIP("2001:0:3238:DFE1:63::FEFC"))
	util.Encode(srcPort, binary.BigEndian, uint16(1234))
	util.Encode(dstPort, binary.BigEndian, uint16(5678))
	util.Encode(proto, binary.BigEndian, uint8(6))
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv6Address", 8, 18, 0, 4), srcAddr)
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv6Address", 12, 18, 0, 4), dstAddr)
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), srcPort)
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), dstPort)
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), proto)
	elements = append(elements, ie1, ie2, ie3, ie4, ie5)
	set.AddRecord(elements, 256)
	return &entities.Message{
		Version:       10,
		BufferLength:  32,
		SeqNumber:     1,
		ObsDomainID:   uint32(1234),
		ExportTime:    0,
		ExportAddress: "::1",
		Set:           set,
	}
}

func TestInitAggregationProcess(t *testing.T) {
	aggregationProcess, err := InitAggregationProcess(nil, 2, fields)
	assert.NotNil(t, err)
	assert.Nil(t, aggregationProcess)
	messageChan := make(chan *entities.Message)
	aggregationProcess, err = InitAggregationProcess(messageChan, 2, fields)
	assert.Nil(t, err)
	assert.Equal(t, 2, aggregationProcess.workerNum)
}

func TestGetTupleRecordMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	assert.Equal(t, aggregationProcess.flowKeyRecordMap, aggregationProcess.flowKeyRecordMap)
}

func TestAggregateMsgByFlowKey(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	// Template records should be ignored
	message := createMsgwithTemplateSet()
	aggregationProcess.AggregateMsgByFlowKey(message)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
	// Data records should be processed and stored with corresponding flow key
	message = createMsgwithDataSet1()
	aggregationProcess.AggregateMsgByFlowKey(message)
	assert.NotEmpty(t, aggregationProcess.flowKeyRecordMap)
	flowKey := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	record := aggregationProcess.flowKeyRecordMap[flowKey][0]
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	ieWithValue, exist := record.GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0xa, 0x0, 0x0, 0x1}, ieWithValue.Value)
	assert.Equal(t, message.Set.GetRecords()[0], record)

	// Data record with IPv6 addresses should be processed and stored correctly
	message = createMsgwithDataSetIPv6()
	aggregationProcess.AggregateMsgByFlowKey(message)
	assert.Equal(t, 2, len(aggregationProcess.flowKeyRecordMap))
	flowKey = FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	assert.NotNil(t, aggregationProcess.flowKeyRecordMap[flowKey])
	record = aggregationProcess.flowKeyRecordMap[flowKey][0]
	ieWithValue, exist = record.GetInfoElementWithValue("sourceIPv6Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0x20, 0x1, 0x0, 0x0, 0x32, 0x38, 0xdf, 0xe1, 0x0, 0x63, 0x0, 0x0, 0x0, 0x0, 0xfe, 0xfb}, ieWithValue.Value)
	assert.Equal(t, message.Set.GetRecords()[0], record)
}

func TestAggregationProcess(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	dataMsg := createMsgwithDataSet1()
	go func() {
		messageChan <- createMsgwithTemplateSet()
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
	registry.LoadRegistry()
	// Test message with template set
	message := createMsgwithTemplateSet()
	addOriginalExporterInfo(message)
	record := message.Set.GetRecords()[0]
	_, exist := record.GetInfoElementWithValue("originalExporterIPv4Address")
	assert.Equal(t, true, exist)
	_, exist = record.GetInfoElementWithValue("originalObservationDomainId")
	assert.Equal(t, true, exist)
	// Test message with data set
	message = createMsgwithDataSet1()
	addOriginalExporterInfo(message)
	record = message.Set.GetRecords()[0]
	ieWithValue, exist := record.GetInfoElementWithValue("originalExporterIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, net.IP{0x7f, 0x0, 0x0, 0x1}, ieWithValue.Value)
	ieWithValue, exist = record.GetInfoElementWithValue("originalObservationDomainId")
	assert.Equal(t, true, exist)
	assert.Equal(t, uint32(1234), ieWithValue.Value)
}

func TestCorrelateRecords(t *testing.T) {
	registry.LoadRegistry()
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	record1 := createMsgwithDataSet1().Set.GetRecords()[0]
	flowKey1, _ := getFlowKeyFromRecord(record1)
	record2 := createMsgwithDataSet2().Set.GetRecords()[0]
	flowKey2, _ := getFlowKeyFromRecord(record2)
	aggregationProcess.correlateRecords(*flowKey1, record1)
	aggregationProcess.correlateRecords(*flowKey2, record2)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	for _, records := range aggregationProcess.flowKeyRecordMap {
		assert.Equal(t, 1, len(records))
		ieWithValue, _ := records[0].GetInfoElementWithValue("sourcePodName")
		assert.Equal(t, "pod1", ieWithValue.Value)
		ieWithValue, _ = records[0].GetInfoElementWithValue("destinationPodName")
		assert.Equal(t, "pod2", ieWithValue.Value)
		ieWithValue, _ = records[0].GetInfoElementWithValue("destinationClusterIP")
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, ieWithValue.Value)
		ieWithValue, _ = records[0].GetInfoElementWithValue("destinationServicePort")
		assert.Equal(t, uint16(4739), ieWithValue.Value)
	}
}

func TestDeleteTupleFromMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	message := createMsgwithDataSet1()
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2, fields)
	flowKey1 := FlowKey{"10.0.0.1", "10.0.0.2", 6, 1234, 5678}
	flowKey2 := FlowKey{"2001:0:3238:dfe1:63::fefb", "2001:0:3238:dfe1:63::fefc", 6, 1234, 5678}
	aggregationProcess.flowKeyRecordMap[flowKey1] = message.Set.GetRecords()
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	aggregationProcess.DeleteFlowKeyFromMap(flowKey2)
	assert.Equal(t, 1, len(aggregationProcess.flowKeyRecordMap))
	aggregationProcess.DeleteFlowKeyFromMap(flowKey1)
	assert.Empty(t, aggregationProcess.flowKeyRecordMap)
}
