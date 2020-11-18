package test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/intermediate"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var templatePacket = []byte{0, 10, 0, 76, 95, 154, 84, 121, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 60, 1, 0, 0, 9, 0, 8, 0, 4, 0, 12, 0, 4, 0, 7, 0, 2, 0, 11, 0, 2, 0, 4, 0, 1, 128, 101, 255, 255, 0, 0, 220, 186, 128, 103, 255, 255, 0, 0, 220, 186, 128, 106, 0, 4, 0, 0, 220, 186, 128, 107, 0, 2, 0, 0, 220, 186}
var dataPacket1 = []byte{0, 10, 0, 45, 95, 154, 80, 113, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 29, 1, 2, 3, 4, 5, 6, 7, 8, 4, 210, 22, 46, 6, 4, 112, 111, 100, 49, 0, 192, 168, 0, 1, 18, 131}
var dataPacket2 = []byte{0, 10, 0, 45, 95, 154, 82, 114, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 29, 1, 2, 3, 4, 5, 6, 7, 8, 4, 210, 22, 46, 6, 0, 4, 112, 111, 100, 50, 0, 0, 0, 0, 0, 0}
var flowKeyRecordMap = make(map[intermediate.FlowKey][]entities.Record)

func TestCollectorToIntermediate(t *testing.T) {
	registry.LoadRegistry()
	var fields = []string{
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
	}
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	// Initialize aggregation process and collecting process
	cp, _ := collector.InitCollectingProcess(address, 1024, 0)
	ap, _ := intermediate.InitAggregationProcess(cp.GetMsgChan(), 2, fields)

	go func() {
		time.Sleep(time.Second)
		conn, err := net.DialUDP("udp", nil, address)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(templatePacket)
		time.Sleep(time.Second)
		conn.Write(dataPacket1)
		time.Sleep(time.Second)
		conn.Write(dataPacket2)
	}()
	go func() {
		ap.Start()
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
		ap.Stop()
	}()
	cp.Start()
	ap.ForAllRecordsDo(copyFlowKeyRecordMap)
	assert.Equal(t, 1, len(flowKeyRecordMap), "Aggregation process should store the data record to map with corresponding flow key.")
	flowKey := intermediate.FlowKey{SourceAddress: "1.2.3.4", DestinationAddress: "5.6.7.8", Protocol: 6, SourcePort: 1234, DestinationPort: 5678}
	assert.NotNil(t, flowKeyRecordMap[flowKey])
	assert.Equal(t, 1, len(flowKeyRecordMap[flowKey]), "Aggregation process should correlate data record and only store one record.")
	record := flowKeyRecordMap[flowKey]
	elements := record[0].GetOrderedElementList()
	assert.Equal(t, "pod1", elements[5].Value)
	ieWithValue, _ := record[0].GetInfoElementWithValue("destinationPodName")
	assert.Equal(t, "pod2", ieWithValue.Value, "Aggregation process should correlate and fill corresponding fields.")
	assert.Equal(t, 11, len(elements), "There should be two more fields for exporter information in the record.")
	ieWithValue, _ = record[0].GetInfoElementWithValue("originalObservationDomainId")
	assert.Equal(t, uint32(1), ieWithValue.Value, "originalObservationDomainId should be added correctly in record.")
}

func copyFlowKeyRecordMap(key intermediate.FlowKey, records []entities.Record) error {
	flowKeyRecordMap[key] = records
	return nil
}
