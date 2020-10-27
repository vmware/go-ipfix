package intermediate

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

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
	elements = append(elements, ie1, ie2, ie3, ie4, ie5)
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

func createMsgwithDataSet() *entities.Message {
	set := entities.NewSet(entities.Data, 256, true)
	elements := make([]*entities.InfoElementWithValue, 0)
	srcPort := new(bytes.Buffer)
	dstPort := new(bytes.Buffer)
	proto := new(bytes.Buffer)
	util.Encode(srcPort, binary.BigEndian, uint16(1234))
	util.Encode(dstPort, binary.BigEndian, uint16(5678))
	util.Encode(proto, binary.BigEndian, uint8(6))
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 1}))
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), bytes.NewBuffer([]byte{10, 0, 0, 2}))
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
	message = createMsgwithDataSet()
	aggregationProcess.AggregateMsgBy5Tuple(message)
	assert.NotEmpty(t, aggregationProcess.GetTupleRecordMap())
	for tuple, records := range aggregationProcess.GetTupleRecordMap() {
		assert.Equal(t, tuple.SourceAddress, uint32(167772161))
		assert.Equal(t, tuple.DestinationAddress, uint32(167772162))
		assert.Equal(t, tuple.SourcePort, uint16(1234))
		assert.Equal(t, tuple.DestinationPort, uint16(5678))
		assert.Equal(t, tuple.Protocol, uint8(6))
		assert.Equal(t, message.Set.GetRecords(), records)
	}
}

func TestAggregationProcess(t *testing.T) {
	messageChan := make(chan *entities.Message)
	aggregationProcess, _ := InitAggregationProcess(messageChan, 2)
	dataMsg := createMsgwithDataSet()
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
		167772161, 167772162, 6, 1234, 5678,
	}
	assert.NotNil(t, aggregationProcess.GetTupleRecordMap()[tuple])
}

func TestAddOriginalExporterInfo(t *testing.T) {
	registry.LoadRegistry()
	// Test message with template set
	message := createMsgwithTemplateSet()
	addOriginalExporterInfo(message)
	record := message.Set.GetRecords()[0]
	assert.Equal(t, "originalExporterIPv4Address", record.GetInfoElements()[5].Element.Name)
	assert.Equal(t, "originalObservationDomainId", record.GetInfoElements()[6].Element.Name)
	// Test message with data set
	message = createMsgwithDataSet()
	addOriginalExporterInfo(message)
	record = message.Set.GetRecords()[0]
	assert.Equal(t, "originalExporterIPv4Address", record.GetInfoElements()[5].Element.Name)
	assert.Equal(t, uint32(2130706433), record.GetInfoElements()[5].Value)
	assert.Equal(t, "originalObservationDomainId", record.GetInfoElements()[6].Element.Name)
	assert.Equal(t, uint32(1234), record.GetInfoElements()[6].Value)
}
