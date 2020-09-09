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
)

type Address struct {
	network string
	port    string
}

func (addr Address) Network() string {
	return addr.network
}

func (addr Address) String() string {
	return "0.0.0.0:" + addr.port
}

var validTemplateRecord = []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
var validDataRecord = []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 89, 105, 111, 117}
var templateFields = []*templateField{
	{8, 4, 0},
	{12, 4, 0},
	{105, 65535, 55829},
}

func TestTCPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address := Address{"tcp", "4730"}
	cp, err := InitCollectingProcess(address, 1024, 0)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validTemplateRecord)
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1], "TCP Collecting Process should receive and store the received template.")
}

func TestUDPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address := Address{"udp", "4731"}
	cp, err := InitCollectingProcess(address, 1024, 0)
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
		conn.Write(validTemplateRecord)
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1], "UDP Collecting Process should receive and store the received template.")
}

func TestTCPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address := Address{"tcp", "4732"}
	cp, err := InitCollectingProcess(address, 1024, 0)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), templateFields)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validDataRecord)
	}()
	go func() {
		time.Sleep(4 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.Equal(t, 1, len(cp.messages), "TCP Collecting Process should receive and store the received data record.")
}

func TestUDPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address := Address{"udp", "4733"}
	cp, err := InitCollectingProcess(address, 1024, 0)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), templateFields)
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
		conn.Write(validDataRecord)
	}()
	go func() {
		time.Sleep(5 * time.Second)
		cp.Stop()
	}()
	cp.Start()
	assert.Equal(t, 1, len(cp.messages), "UDP Collecting Process should receive and store the received data record.")
}

func TestTCPCollectingProcess_ConcurrentClient(t *testing.T) {
	address := Address{"tcp", "4734"}
	cp, _ := InitCollectingProcess(address, 1024, 0)
	go func() {
		time.Sleep(time.Second)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
	}()
	go func() {
		time.Sleep(time.Second)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
		time.Sleep(2 * time.Second)
		assert.Equal(t, 2, cp.getClientCount(), "There should be two tcp clients.")
		cp.Stop()
	}()
	cp.Start()
}

func TestUDPCollectingProcess_ConcurrentClient(t *testing.T) {
	address := Address{"udp", "4735"}
	cp, _ := InitCollectingProcess(address, 1024, 0)
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
		conn.Write(validTemplateRecord)
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
		conn.Write(validTemplateRecord)
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
	cp.templatesMap = make(map[uint32]map[uint16][]*templateField)
	cp.templatesLock = sync.RWMutex{}
	cp.address = Address{"tcp", "4736"}
	message, err := cp.decodePacket(bytes.NewBuffer(validTemplateRecord))
	if err != nil {
		t.Fatalf("Got error in decoding template record: %v", err)
	}
	assert.Equal(t, uint16(10), message.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, message.Record, "Template record should be stored in message flowset")
	assert.NotNil(t, cp.templatesMap[message.ObsDomainID], "Template should be stored in template map")
	// Invalid version
	templateRecord := []byte{0, 9, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
	message, err = cp.decodePacket(bytes.NewBuffer(templateRecord))
	assert.NotNil(t, err, "Error should be logged for invalid version")
	// Malformed record
	templateRecord = []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0}
	cp.templatesMap = make(map[uint32]map[uint16][]*templateField)
	message, err = cp.decodePacket(bytes.NewBuffer(templateRecord))
	assert.NotNil(t, err, "Error should be logged for malformed template record")
	if _, exist := cp.templatesMap[uint32(1)]; exist {
		t.Fatal("Template should not be stored for malformed template record")
	}
}

func TestCollectingProcess_DecodeDataRecord(t *testing.T) {
	cp := collectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*templateField)
	cp.templatesLock = &sync.RWMutex{}
	cp.address = Address{"tcp", "4737"}
	// Decode without template
	_, err := cp.decodePacket(bytes.NewBuffer(validDataRecord))
	assert.NotNil(t, err, "Error should be logged if corresponding template does not exist.")
	// Decode with template
	cp.addTemplate(uint32(1), uint16(256), templateFields)
	message, err := cp.decodePacket(bytes.NewBuffer(validDataRecord))
	assert.Nil(t, err, "Error should not be logged if corresponding template exists.")
	assert.Equal(t, uint16(10), message.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, message.Record, "Data record should be stored in message set")
	// Malformed data record
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.decodePacket(bytes.NewBuffer(dataRecord))
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	address := Address{"udp", "4738"}
	cp, err := InitCollectingProcess(address, 1024, 5)
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
		_, err = conn.Write(validTemplateRecord)
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
