package test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/intermediate"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var templatePacket = []byte{0, 10, 0, 44, 95, 140, 234, 80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 28, 1, 0, 0, 5, 0, 8, 0, 4, 0, 12, 0, 4, 0, 7, 0, 2, 0, 11, 0, 2, 0, 4, 0, 1}
var dataPacket = []byte{0, 10, 0, 33, 95, 140, 234, 81, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 10, 0, 0, 1, 10, 0, 0, 2, 4, 210, 22, 46, 6}

func TestCollectorToIntermediate(t *testing.T) {
	registry.LoadRegistry()
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	// Initialize aggregation process and collecting process
	cp, _ := collector.InitCollectingProcess(address, 1024, 0, true)
	ap, _ := intermediate.InitAggregationProcess(cp.GetMsgChan(), 2)

	go func() {
		time.Sleep(time.Second)
		conn, err := net.DialUDP("udp", nil, address)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(templatePacket)
		time.Sleep(time.Second)
		conn.Write(dataPacket)
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
	assert.Equal(t, 1, len(ap.GetTupleRecordMap()), "Aggregation process should store the data record to map with corresponding tuple.")
	tuple := intermediate.Tuple{SourceAddress: 167772161, DestinationAddress: 167772162, Protocol: 6, SourcePort: 1234, DestinationPort: 5678}
	assert.NotNil(t, ap.GetTupleRecordMap()[tuple])
	record := ap.GetTupleRecordMap()[tuple]
	elements := record[0].GetInfoElements()
	assert.Equal(t, 7, len(elements), "There should be two more fields for exporter information in the record.")
	assert.Equal(t, uint32(1), elements[6].Value, "originalObservationDomainId should be added correctly in record.")
}
