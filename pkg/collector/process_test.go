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
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/test"
)

var validTemplatePacket = []byte{0, 10, 0, 40, 95, 154, 107, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 101, 255, 255, 0, 0, 220, 186}
var validTemplatePacketIPv6 = []byte{0, 10, 0, 32, 96, 27, 70, 6, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 16, 1, 0, 0, 2, 0, 27, 0, 16, 0, 28, 0, 16}
var validDataPacket = []byte{0, 10, 0, 33, 95, 154, 108, 18, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 112, 111, 100, 49}
var validDataPacketIPv6 = []byte{0, 10, 0, 52, 96, 27, 75, 252, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 36, 32, 1, 0, 0, 50, 56, 223, 225, 0, 99, 0, 0, 0, 0, 254, 251, 32, 1, 0, 0, 50, 56, 223, 225, 0, 99, 0, 0, 0, 0, 254, 251}

const (
	tcpTransport = "tcp"
	udpTransport = "udp"
	hostPortIPv4 = "127.0.0.1:0"
	hostPortIPv6 = "[::1]:0"
)

var elementsWithValueIPv4 = []entities.InfoElementWithValue{
	{Element: &entities.InfoElement{Name: "sourceIPv4Address", ElementId: 8, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationIPv4Address", ElementId: 12, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationNodeName", ElementId: 105, DataType: 13, EnterpriseId: 55829, Len: 65535}, Value: nil},
}

func init() {
	registry.LoadRegistry()
}

func TestTCPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	go func() {
		conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "TCP Collecting Process should receive and store the received template.")
}

func TestUDPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	input := getCollectorInput(udpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	go func() {
		resolveAddr, err := net.ResolveUDPAddr(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP(udpTransport, nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "UDP Collecting Process should receive and store the received template.")

}

func TestTCPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValueIPv4)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}

	go cp.Start()

	// wait until collector is ready
	waitForCollectorReady(t, cp)
	var conn net.Conn
	collectorAddr := cp.GetAddress()
	go func() {
		conn, err = net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
		conn.Write(validDataPacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	// Check if connection has closed properly or not by trying to write to it
	_, err = conn.Write(validDataPacket)
	time.Sleep(time.Millisecond)
	_, err = conn.Write(validDataPacket)
	assert.Error(t, err)
	conn.Close()
	// Check if connection has closed properly or not by trying to create a new connection.
	_, err = net.Dial(collectorAddr.Network(), collectorAddr.String())
	assert.Error(t, err)
}

func TestUDPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	input := getCollectorInput(udpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValueIPv4)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValueIPv4)

	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	resolveAddr, err := net.ResolveUDPAddr(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		t.Errorf("UDP Address cannot be resolved.")
	}
	go func() {
		<-cp.GetMsgChan()
		cp.Stop()
	}()
	conn, err := net.DialUDP(udpTransport, nil, resolveAddr)
	if err != nil {
		t.Errorf("UDP Collecting Process does not start correctly.")
	}
	conn.Write(validDataPacket)
	time.Sleep(time.Millisecond)
	// Check if connection has closed properly or not by trying to write to it
	_, _ = conn.Write(validDataPacket)
	time.Sleep(time.Millisecond)
	_, err = conn.Write(validDataPacket)
	assert.Error(t, err)
	conn.Close()
}

func TestTCPCollectingProcess_ConcurrentClient(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, false)
	cp, _ := InitCollectingProcess(input)
	go func() {
		// wait until collector is ready
		waitForCollectorReady(t, cp)
		collectorAddr := cp.GetAddress()
		_, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
	}()
	go func() {
		// wait until collector is ready
		waitForCollectorReady(t, cp)
		collectorAddr := cp.GetAddress()
		_, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
		time.Sleep(time.Millisecond)
		assert.GreaterOrEqual(t, cp.getClientCount(), 2, "There should be at least two tcp clients.")
		cp.Stop()
	}()
	cp.Start()
}

func TestUDPCollectingProcess_ConcurrentClient(t *testing.T) {
	input := getCollectorInput(udpTransport, false, false)
	cp, _ := InitCollectingProcess(input)
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	resolveAddr, err := net.ResolveUDPAddr(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		t.Errorf("UDP Address cannot be resolved.")
	}
	conn1, err := net.DialUDP(udpTransport, nil, resolveAddr)
	if err != nil {
		t.Errorf("UDP Collecting Process does not start correctly.")
	}
	defer conn1.Close()
	conn1.Write(validTemplatePacket)

	conn2, err := net.DialUDP(udpTransport, nil, resolveAddr)
	if err != nil {
		t.Errorf("UDP Collecting Process does not start correctly.")
	}
	defer conn2.Close()
	conn2.Write(validTemplatePacket)
	time.Sleep(time.Millisecond)
	assert.GreaterOrEqual(t, cp.getClientCount(), 2, "There should be at least two udp clients.")
	// there should be two messages received
	<-cp.GetMsgChan()
	<-cp.GetMsgChan()
	cp.Stop()
}

func TestCollectingProcess_DecodeTemplateRecord(t *testing.T) {
	cp := CollectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.mutex = sync.RWMutex{}
	address, err := net.ResolveTCPAddr(tcpTransport, hostPortIPv4)
	if err != nil {
		t.Error(err)
	}
	cp.netAddress = address
	cp.messageChan = make(chan *entities.Message)
	go func() { // remove the message from the message channel
		for range cp.GetMsgChan() {
		}
	}()
	message, err := cp.decodePacket(bytes.NewBuffer(validTemplatePacket), address.String())
	if err != nil {
		t.Fatalf("Got error in decoding template record: %v", err)
	}
	assert.Equal(t, uint16(10), message.GetVersion(), "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.GetObsDomainID(), "Flow record obsDomainID should be 1.")
	assert.NotNil(t, cp.templatesMap[message.GetObsDomainID()], "Template should be stored in template map")

	templateSet := message.GetSet()
	assert.NotNil(t, templateSet, "Template record should be stored in message flowset")
	sourceIPv4Address, _, exist := templateSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, uint32(0), sourceIPv4Address.Element.EnterpriseId, "Template record is not stored correctly.")
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
	cp := CollectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.mutex = sync.RWMutex{}
	address, err := net.ResolveTCPAddr(tcpTransport, hostPortIPv4)
	if err != nil {
		t.Error(err)
	}
	cp.netAddress = address
	cp.messageChan = make(chan *entities.Message)
	go func() { // remove the message from the message channel
		for range cp.GetMsgChan() {
		}
	}()
	// Decode without template
	_, err = cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.NotNil(t, err, "Error should be logged if corresponding template does not exist.")
	// Decode with template
	cp.addTemplate(uint32(1), uint16(256), elementsWithValueIPv4)
	message, err := cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.Nil(t, err, "Error should not be logged if corresponding template exists.")
	assert.Equal(t, uint16(10), message.GetVersion(), "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.GetObsDomainID(), "Flow record obsDomainID should be 1.")

	set := message.GetSet()
	assert.NotNil(t, set, "Data set should be stored in message set")
	ipAddress := net.IP([]byte{1, 2, 3, 4})
	sourceIPv4Address, _, exist := set.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, ipAddress, sourceIPv4Address.Value, "sourceIPv4Address should be decoded and stored correctly.")
	// Malformed data record
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.decodePacket(bytes.NewBuffer(dataRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	input := CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      udpTransport,
		MaxBufferSize: 1024,
		TemplateTTL:   1,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	go func() {
		resolveAddr, err := net.ResolveUDPAddr(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP(udpTransport, nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		if err != nil {
			t.Errorf("Error in sending data to collector: %v", err)
		}
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, err := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "Template should be stored in the template map.")
	assert.Nil(t, err, "Template should be stored in the template map.")
	time.Sleep(2 * time.Second)
	template, err = cp.getTemplate(1, 256)
	assert.Nil(t, template, "Template should be deleted after 5 seconds.")
	assert.NotNil(t, err, "Template should be deleted after 5 seconds.")
}

func TestTLSCollectingProcess(t *testing.T) {
	input := getCollectorInput(tcpTransport, true, false)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("Collecting Process does not initiate correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	var conn net.Conn
	var config *tls.Config
	go func() {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(test.FakeCACert))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		cert, err := tls.X509KeyPair([]byte(test.FakeClientCert), []byte(test.FakeClientKey))
		if err != nil {
			t.Error(err)
		}
		config = &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		}

		conn, err = tls.Dial("tcp", collectorAddr.String(), config)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = conn.Write(validTemplatePacket)
		assert.NoError(t, err)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	assert.NotNil(t, cp.templatesMap[1], "TLS Collecting Process should receive and store the received template.")
	// Check if connection has closed properly or not by trying to write to it
	_, _ = conn.Write(validDataPacket)
	time.Sleep(time.Millisecond)
	_, err = conn.Write(validDataPacket)
	assert.Error(t, err)
	conn.Close()
	// Check if connection has closed properly or not by trying to create a new connection.
	_, err = tls.Dial(collectorAddr.Network(), collectorAddr.String(), config)
	assert.Error(t, err)
}

func TestDTLSCollectingProcess(t *testing.T) {
	input := getCollectorInput(udpTransport, true, false)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("DTLS Collecting Process does not initiate correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr, _ := net.ResolveUDPAddr("udp", cp.GetAddress().String())
	go func() {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(test.FakeCert2))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		config := &dtls.Config{RootCAs: roots,
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret}
		conn, err := dtls.Dial("udp", collectorAddr, config)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		assert.NoError(t, err)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	assert.NotNil(t, cp.templatesMap[1], "DTLS Collecting Process should receive and store the received template.")
}

func TestTCPCollectingProcessIPv6(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, true)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	go func() {
		conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
		defer conn.Close()
		conn.Write(validTemplatePacketIPv6)
		conn.Write(validDataPacketIPv6)
	}()
	<-cp.GetMsgChan()
	message := <-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template)
	ie, _, exist := message.GetSet().GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.True(t, exist)
	assert.Equal(t, net.ParseIP("2001:0:3238:DFE1:63::FEFB"), ie.Value)
}

func TestUDPCollectingProcessIPv6(t *testing.T) {
	input := getCollectorInput(udpTransport, false, true)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	go func() {
		conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", collectorAddr.String())
		}
		defer conn.Close()
		conn.Write(validTemplatePacketIPv6)
		conn.Write(validDataPacketIPv6)
	}()
	<-cp.GetMsgChan()
	message := <-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template)
	ie, _, exist := message.GetSet().GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.True(t, exist)
	assert.Equal(t, net.ParseIP("2001:0:3238:DFE1:63::FEFB"), ie.Value)
}

func getCollectorInput(network string, isEncrypted bool, isIPv6 bool) CollectorInput {
	if network == tcpTransport {
		var address string
		if isIPv6 {
			address = hostPortIPv6
		} else {
			address = hostPortIPv4
		}
		if isEncrypted {
			return CollectorInput{
				Address:       address,
				Protocol:      tcpTransport,
				MaxBufferSize: 1024,
				TemplateTTL:   0,
				IsEncrypted:   true,
				CACert:        []byte(test.FakeCACert),
				ServerCert:    []byte(test.FakeCert),
				ServerKey:     []byte(test.FakeKey),
			}
		} else {
			return CollectorInput{
				Address:       address,
				Protocol:      tcpTransport,
				MaxBufferSize: 1024,
			}
		}
	} else {
		var address string
		if isIPv6 {
			address = hostPortIPv6
		} else {
			address = hostPortIPv4
		}
		if isEncrypted {
			return CollectorInput{
				Address:       address,
				Protocol:      udpTransport,
				MaxBufferSize: 1024,
				TemplateTTL:   0,
				IsEncrypted:   true,
				ServerCert:    []byte(test.FakeCert2),
				ServerKey:     []byte(test.FakeKey2),
			}
		} else {
			return CollectorInput{
				Address:       address,
				Protocol:      udpTransport,
				MaxBufferSize: 1024,
			}
		}
	}
}

func waitForCollectorReady(t *testing.T, cp *CollectingProcess) {
	checkConn := func() (bool, error) {
		if conn, err := net.Dial(cp.GetAddress().Network(), cp.GetAddress().String()); err != nil {
			return false, err
		} else {
			defer conn.Close()
			return true, nil
		}
	}
	if err := wait.Poll(100*time.Millisecond, 500*time.Millisecond, checkConn); err != nil {
		t.Errorf("Cannot establish connection to %s", cp.GetAddress().String())
	}
}
