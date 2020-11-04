package intermediate

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
)

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
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 1}))
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 2}))
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

func TestInitAggregationProcess(t *testing.T) {
	aggregationProcess, err := InitAggregationProcess(nil, 2)
	assert.NotNil(t, err)
	assert.Nil(t, aggregationProcess)
	messageChan := make(chan *entities.Message)
	aggregationProcess, err = InitAggregationProcess(messageChan, 2)
	assert.Nil(t, err)
	assert.Equal(t, 2, aggregationProcess.workerNum)
}

func TestGetTupleRecordMap(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2)
	assert.Equal(t, aggregationProcess.tupleRecordMap, aggregationProcess.GetTupleRecordMap())
}

func TestAggregateMsgBy5Tuple(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2)
	// Template records should be ignored
	message := createMsgwithTemplateSet()
	aggregationProcess.AggregateMsgBy5Tuple(message)
	assert.Empty(t, aggregationProcess.GetTupleRecordMap())
	// Data records should be processed and stored with corresponding tuple
	message = createMsgwithDataSet1()
	aggregationProcess.AggregateMsgBy5Tuple(message)
	assert.NotEmpty(t, aggregationProcess.GetTupleRecordMap())
	for tuple, records := range aggregationProcess.GetTupleRecordMap() {
		assert.Equal(t, tuple.SourceAddress, [16]byte{10: 255, 11: 255, 12: 10, 15: 1})
		assert.Equal(t, tuple.DestinationAddress, [16]byte{10: 255, 11: 255, 12: 10, 15: 2})
		assert.Equal(t, tuple.SourcePort, uint16(1234))
		assert.Equal(t, tuple.DestinationPort, uint16(5678))
		assert.Equal(t, tuple.Protocol, uint8(6))
		assert.Equal(t, message.Set.GetRecords(), records)
	}
}

func TestAggregationProcess(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2)
	dataMsg := createMsgwithDataSet1()
	go func() {
		messageChan <- createMsgwithTemplateSet()
		time.Sleep(time.Second)
		messageChan <- dataMsg
		time.Sleep(time.Second)
		close(messageChan)
		aggregationProcess.Stop()
	}()
	aggregationProcess.Start()
	tuple := Tuple{
		[16]byte{10: 255, 11: 255, 12: 10, 15: 1}, [16]byte{10: 255, 11: 255, 12: 10, 15: 2}, 6, 1234, 5678,
	}
	assert.NotNil(t, aggregationProcess.GetTupleRecordMap()[tuple])
}

func TestAddOriginalExporterInfo(t *testing.T) {
	registry.LoadRegistry()
	// Test message with template set
	message := createMsgwithTemplateSet()
	addOriginalExporterInfo(message)
	record := message.Set.GetRecords()[0]
	assert.Equal(t, true, record.ContainsInfoElement("originalExporterIPv4Address"))
	assert.Equal(t, true, record.ContainsInfoElement("originalObservationDomainId"))
	// Test message with data set
	message = createMsgwithDataSet1()
	addOriginalExporterInfo(message)
	record = message.Set.GetRecords()[0]
	klog.Info(record.GetInfoElements())
	assert.Equal(t, true, record.ContainsInfoElement("originalExporterIPv4Address"))
	assert.Equal(t, net.IP{0x7f, 0x0, 0x0, 0x1}, record.GetInfoElement("originalExporterIPv4Address").Value)
	assert.Equal(t, true, record.ContainsInfoElement("originalObservationDomainId"))
	assert.Equal(t, uint32(1234), record.GetInfoElement("originalObservationDomainId").Value)
}

func TestCorrelateRecords(t *testing.T) {
	registry.LoadRegistry()
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2)
	record1 := createMsgwithDataSet1().Set.GetRecords()[0]
	tuple1, _ := getTupleFromRecord(record1)
	record2 := createMsgwithDataSet2().Set.GetRecords()[0]
	tuple2, _ := getTupleFromRecord(record2)
	aggregationProcess.correlateRecords(tuple1, record1)
	aggregationProcess.correlateRecords(tuple2, record2)
	assert.Equal(t, 1, len(aggregationProcess.GetTupleRecordMap()))
	for _, records := range aggregationProcess.GetTupleRecordMap() {
		assert.Equal(t, 1, len(records))
		assert.Equal(t, "pod1", records[0].GetInfoElement("sourcePodName").Value)
		assert.Equal(t, "pod2", records[0].GetInfoElement("destinationPodName").Value)
		assert.Equal(t, net.IP{0xc0, 0xa8, 0x0, 0x1}, records[0].GetInfoElement("destinationClusterIP").Value)
		assert.Equal(t, uint16(4739), records[0].GetInfoElement("destinationServicePort").Value)
	}
}
