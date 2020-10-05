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

package collector

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var validTemplatePacket = []byte{0, 10, 0, 40, 95, 154, 107, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 101, 255, 255, 0, 0, 220, 186}
var validDataPacket = []byte{0, 10, 0, 33, 95, 154, 108, 18, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 112, 111, 100, 49}
var elementsWithValue = []*entities.InfoElementWithValue{
	{Element: &entities.InfoElement{Name: "sourceIPv4Address", ElementId: 8, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationIPv4Address", ElementId: 12, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationNodeName", ElementId: 105, DataType: 13, EnterpriseId: 55829, Len: 65535}, Value: nil},
}

func init() {
	registry.LoadRegistry()
}

func TestTCPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4730")
	if err != nil {
		t.Error(err)
	}
	cp, err := InitCollectingProcess(address, 1024, 0, nil)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1], "TCP Collecting Process should receive and store the received template.")
}

func TestUDPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4731")
	if err != nil {
		t.Error(err)
	}
	cp, err := InitCollectingProcess(address, 1024, 0, nil)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1], "UDP Collecting Process should receive and store the received template.")
}

func TestTCPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4732")
	if err != nil {
		t.Error(err)
	}
	messageChan := make(chan *entities.Message)
	messageCount := 0
	cp, err := InitCollectingProcess(address, 1024, 0, messageChan)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validDataPacket)
		for range messageChan {
			messageCount++
		}
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.Equal(t, 1, messageCount, "TCP Collecting Process should receive and store the received data record.")
}

func TestUDPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4733")
	if err != nil {
		t.Error(err)
	}
	messageChan := make(chan *entities.Message)
	messageCount := 0
	cp, err := InitCollectingProcess(address, 1024, 0, messageChan)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validDataPacket)
		for range messageChan {
			messageCount++
		}
	}()
	go func() {
		time.Sleep(5 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.Equal(t, 1, messageCount, "UDP Collecting Process should receive and store the received data record.")
}

func TestTCPCollectingProcess_ConcurrentClient(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4734")
	if err != nil {
		t.Error(err)
	}
	cp, _ := InitCollectingProcess(address, 1024, 0, nil)
	go func() {
		time.Sleep(time.Second)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
	}()
	go func() {
		time.Sleep(time.Second)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		time.Sleep(2 * time.Second)
		assert.Equal(t, 2, cp.getClientCount(), "There should be two tcp clients.")
		cp.Stop()
	}()
	cp.Start()
}

func TestUDPCollectingProcess_ConcurrentClient(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4735")
	if err != nil {
		t.Error(err)
	}
	cp, _ := InitCollectingProcess(address, 1024, 0, nil)
	go func() {
		time.Sleep(time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	go func() {
		time.Sleep(time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
		time.Sleep(time.Second)
		assert.Equal(t, 2, len(cp.clients), "There should be two tcp clients.")
	}()
	go func() {
		time.Sleep(6 * time.Second)
		cp.Stop()
	}()
	cp.Start()
}

func TestCollectingProcess_DecodeTemplateRecord(t *testing.T) {
	cp := collectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.templatesLock = sync.RWMutex{}
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4736")
	if err != nil {
		t.Error(err)
	}
	cp.address = address
	message, err := cp.decodePacket(bytes.NewBuffer(validTemplatePacket), address.String())
	if err != nil {
		t.Fatalf("Got error in decoding template record: %v", err)
	}
	assert.Equal(t, uint16(10), message.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, message.Set, "Template record should be stored in message flowset")
	assert.NotNil(t, cp.templatesMap[message.ObsDomainID], "Template should be stored in template map")
	templateSet, ok := message.Set.(entities.Set)
	if !ok {
		t.Error("Template packet is not decoded correctly.")
	}
	elements := templateSet.GetRecords()[0].GetInfoElements()
	assert.Equal(t, uint32(0), elements[0].Element.EnterpriseId, "Template record is not stored correctly.")
	// Invalid version
	templateRecord := []byte{0, 9, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
	_, err = cp.decodePacket(bytes.NewBuffer(templateRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for invalid version")
	// Malformed record
	templateRecord = []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	_, err = cp.decodePacket(bytes.NewBuffer(templateRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed template record")
	if _, exist := cp.templatesMap[uint32(1)]; exist {
		t.Fatal("Template should not be stored for malformed template record")
	}
}

func TestCollectingProcess_DecodeDataRecord(t *testing.T) {
	cp := collectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.templatesLock = sync.RWMutex{}
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4737")
	if err != nil {
		t.Error(err)
	}
	cp.address = address
	// Decode without template
	_, err = cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.NotNil(t, err, "Error should be logged if corresponding template does not exist.")
	// Decode with template
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	message, err := cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.Nil(t, err, "Error should not be logged if corresponding template exists.")
	assert.Equal(t, uint16(10), message.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, message.Set, "Data set should be stored in message set")
	v, ok := message.Set.(entities.Set)
	if !ok {
		t.Error("Message.Set does not store data in correct format")
	}
	ipAddress := net.IP([]byte{1, 2, 3, 4})
	elements := v.GetRecords()[0].GetInfoElements()
	assert.Equal(t, ipAddress, elements[0].Value, "sourceIPv4Address should be decoded and stored correctly.")
	assert.Equal(t, uint32(0), elements[3].Value, "originalExporterIPv4Address should be added to record correctly.")
	assert.Equal(t, uint32(1), elements[4].Value, "originalObservationDomainId should be added to record correctly.")
	// Malformed data record
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.decodePacket(bytes.NewBuffer(dataRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4738")
	if err != nil {
		t.Error(err)
	}
	cp, err := InitCollectingProcess(address, 1024, 5, nil)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		if err != nil {
			t.Errorf("Error in sending data to collector: %v", err)
		}
	}()
	go func() {
		time.Sleep(5 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1][256], "Template should be stored in the template map.")
	time.Sleep(10 * time.Second)
	assert.Nil(t, cp.templatesMap[1][256], "Template should be deleted after 5 seconds.")
}

func TestAddOriginalExporterInfo(t *testing.T) {
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

func createMsgwithTemplateSet() *entities.Message {
	set := entities.NewSet(entities.Template, 256, false)
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
	set := entities.NewSet(entities.Data, 256, false)
	elements := make([]*entities.InfoElementWithValue, 0)
	ie1 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceIPv4Address", 8, 18, 0, 4), net.ParseIP("10.0.0.1"))
	ie2 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationIPv4Address", 12, 18, 0, 4), net.ParseIP("10.0.0.2"))
	ie3 := entities.NewInfoElementWithValue(entities.NewInfoElement("sourceTransportPort", 7, 2, 0, 2), uint16(1234))
	ie4 := entities.NewInfoElementWithValue(entities.NewInfoElement("destinationTransportPort", 11, 2, 0, 2), uint16(5678))
	ie5 := entities.NewInfoElementWithValue(entities.NewInfoElement("protocolIdentifier", 4, 1, 0, 1), uint8(6))
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
