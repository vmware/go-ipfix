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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
	testcerts "github.com/vmware/go-ipfix/pkg/test/certs"
)

var (
	validTemplatePacket     = []byte{0, 10, 0, 40, 95, 154, 107, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 101, 255, 255, 0, 0, 220, 186}
	validTemplatePacketIPv6 = []byte{0, 10, 0, 32, 96, 27, 70, 6, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 16, 1, 0, 0, 2, 0, 27, 0, 16, 0, 28, 0, 16}
	validDataPacket         = []byte{0, 10, 0, 33, 95, 154, 108, 18, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 112, 111, 100, 49}
	validDataPacketIPv6     = []byte{0, 10, 0, 52, 96, 27, 75, 252, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 36, 32, 1, 0, 0, 50, 56, 223, 225, 0, 99, 0, 0, 0, 0, 254, 251, 32, 1, 0, 0, 50, 56, 223, 225, 0, 99, 0, 0, 0, 0, 254, 251}

	invalidTemplatePacketWrongVersion = []byte{0, 9, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
)

const (
	tcpTransport = "tcp"
	udpTransport = "udp"
	hostPortIPv4 = "127.0.0.1:0"
	hostPortIPv6 = "[::1]:0"
)

var elementsWithValueIPv4 = []entities.InfoElementWithValue{
	entities.NewIPAddressInfoElement(&entities.InfoElement{Name: "sourceIPv4Address", ElementId: 8, DataType: 18, EnterpriseId: 0, Len: 4}, nil),
	entities.NewIPAddressInfoElement(&entities.InfoElement{Name: "destinationIPv4Address", ElementId: 12, DataType: 18, EnterpriseId: 0, Len: 4}, nil),
	entities.NewStringInfoElement(&entities.InfoElement{Name: "destinationNodeName", ElementId: 105, DataType: 13, EnterpriseId: 55829, Len: 65535}, ""),
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
	template, _ := cp.getTemplateIEs(1, 256)
	assert.NotNil(t, template, "TCP Collecting Process should receive and store the received template.")
	assert.Equal(t, int64(1), cp.GetNumRecordsReceived())
}

func TestTCPCollectingProcess_ReceiveInvalidTemplateRecord(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, cp)
	go func() {
		// consume all messages to avoid blocking
		ch := cp.GetMsgChan()
		for range ch {
		}
	}()
	collectorAddr := cp.GetAddress()
	// client
	conn, err := net.Dial(collectorAddr.Network(), collectorAddr.String())
	if err != nil {
		t.Errorf("Cannot establish connection to %s", collectorAddr.String())
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	conn.Write(invalidTemplatePacketWrongVersion)
	readBuffer := make([]byte, 100)
	_, err = conn.Read(readBuffer)
	assert.ErrorIs(t, err, io.EOF)
	cp.Stop()
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
	template, _ := cp.getTemplateIEs(1, 256)
	assert.NotNil(t, template, "UDP Collecting Process should receive and store the received template.")
	assert.Equal(t, int64(1), cp.GetNumRecordsReceived())
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
	assert.Equal(t, int64(1), cp.GetNumRecordsReceived())
}

// This test was added to easily measure memory usage when collecting and storing data records.
func TestTCPCollectingProcess_ReceiveDataRecordsMemoryUsage(t *testing.T) {
	input := getCollectorInput(tcpTransport, false, false)
	cp, err := InitCollectingProcess(input)
	require.NoError(t, err)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValueIPv4)

	go cp.Start()

	// wait until collector is ready
	waitForCollectorReady(t, cp)

	var conn net.Conn
	collectorAddr := cp.GetAddress()
	conn, err = net.Dial(collectorAddr.Network(), collectorAddr.String())
	require.NoError(t, err)

	const numRecords = 1000

	// We collect the IEs containing the source IPv4 address from all the records received by
	// the collector. We need to make sure that we access the values from this slice *after*
	// running the garbage collector and collecting memory stats, otherwise everything may be
	// garbage collected too early and the results of the test will be inaccurate.
	ies := make([]entities.InfoElementWithValue, 0, numRecords)

	t.Logf("Data packet length: %d", len(validDataPacket))

	for i := 0; i < numRecords; i++ {
		conn.Write(validDataPacket)
		message := <-cp.GetMsgChan()
		set := message.GetSet()
		require.NotNil(t, set)
		records := set.GetRecords()
		require.NotEmpty(t, records)
		ie, _, exist := records[0].GetInfoElementWithValue("sourceIPv4Address")
		require.True(t, exist)
		ies = append(ies, ie)
	}

	conn.Close()
	cp.Stop()

	// Force the GC to run before collecting memory stats
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	ipAddress := net.IP([]byte{1, 2, 3, 4})
	for _, ie := range ies {
		ip := ie.GetIPAddressValue()
		assert.Equal(t, ipAddress, ip)
	}

	t.Logf("Live objects: %d\n", m.Mallocs-m.Frees)
	t.Logf("Bytes of allocated heap objects: %d\n", m.HeapAlloc)
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
	assert.Equal(t, int64(1), cp.GetNumRecordsReceived())
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
		assert.GreaterOrEqual(t, cp.GetNumConnToCollector(), int64(2), "There should be at least two tcp clients.")
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
	assert.GreaterOrEqual(t, cp.GetNumConnToCollector(), int64(2), "There should be at least two udp clients.")
	// there should be two messages received
	<-cp.GetMsgChan()
	<-cp.GetMsgChan()
	cp.Stop()
}

func TestUDPCollectingProcess_DecodePacketError(t *testing.T) {
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

	defer cp.CloseMsgChan()
	go func() {
		// consume all messages to avoid blocking
		ch := cp.GetMsgChan()
		for range ch {
		}
	}()

	conn, err := net.DialUDP(udpTransport, nil, resolveAddr)
	if err != nil {
		t.Errorf("UDP Collecting Process does not start correctly.")
	}
	defer conn.Close()
	// write data packet before template, decodePacket should fail
	conn.Write(validDataPacket)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Equal(t, int64(1), cp.GetNumConnToCollector())
	}, 100*time.Millisecond, 10*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	assert.Zero(t, cp.GetNumRecordsReceived())

	conn.Write(validTemplatePacket)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		assert.Equal(t, int64(1), cp.GetNumConnToCollector())
		assert.Equal(t, int64(1), cp.GetNumRecordsReceived())
	}, 100*time.Millisecond, 10*time.Millisecond)

	cp.Stop()
}

func TestCollectingProcess_DecodeTemplateRecord(t *testing.T) {
	// This is the observation domain ID used by test template records
	const obsDomainID = uint32(1)
	// This is the template ID used by test template records
	const templateID = uint16(256)

	testCases := []struct {
		name              string
		existingTemplates map[uint32]map[uint16]*template
		templateRecord    []byte
		expectedErr       string
		// whether an entry is expected in the templates map after decoding the packet
		isTemplateExpected bool
	}{
		{
			name:               "valid template",
			existingTemplates:  map[uint32]map[uint16]*template{},
			templateRecord:     validTemplatePacket,
			isTemplateExpected: true,
		},
		{
			name: "invalid version",
			existingTemplates: map[uint32]map[uint16]*template{
				obsDomainID: {
					templateID: &template{},
				},
			},
			templateRecord: invalidTemplatePacketWrongVersion,
			expectedErr:    "collector only supports IPFIX (v10)",
			// Invalid  version means we stop decoding the packet right away, so we will not modify the existing template map
			isTemplateExpected: true,
		},
		{
			name: "malformed record fields",
			existingTemplates: map[uint32]map[uint16]*template{
				obsDomainID: {
					templateID: &template{},
				},
			},
			templateRecord:     []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0},
			expectedErr:        "error in decoding data",
			isTemplateExpected: false,
		},
		{
			name: "malformed record header",
			existingTemplates: map[uint32]map[uint16]*template{
				obsDomainID: {
					templateID: &template{},
				},
			},
			// We truncate the record header (3 bytes instead of 4)
			templateRecord: []byte{0, 10, 0, 40, 95, 154, 107, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0},
			expectedErr:    "error in decoding data",
			// If we cannot decode the message to get a template ID, then the existing template entry will not be removed
			isTemplateExpected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cp := CollectingProcess{}
			cp.templatesMap = tc.existingTemplates
			cp.mutex = sync.RWMutex{}
			address, err := net.ResolveTCPAddr(tcpTransport, hostPortIPv4)
			require.NoError(t, err)
			cp.netAddress = address
			cp.messageChan = make(chan *entities.Message)
			go func() { // remove the message from the message channel
				for range cp.GetMsgChan() {
				}
			}()
			message, err := cp.decodePacket(bytes.NewBuffer(tc.templateRecord), address.String())
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err, "failed to decode template record")

				assert.Equal(t, uint16(10), message.GetVersion(), "Unexpected IPFIX version in message")
				assert.Equal(t, obsDomainID, message.GetObsDomainID(), "Unexpected obsDomainID in message")

				templateSet := message.GetSet()
				assert.NotNil(t, templateSet, "Template record should be stored in message flowset")
				sourceIPv4Address, _, exist := templateSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
				assert.Equal(t, true, exist)
				assert.Equal(t, uint32(0), sourceIPv4Address.GetInfoElement().EnterpriseId, "Template record is not stored correctly.")
			}
			if tc.isTemplateExpected {
				assert.NotNil(t, cp.templatesMap[obsDomainID][templateID], "Template should be stored in template map")
			} else {
				assert.Nil(t, cp.templatesMap[obsDomainID][templateID], "Template should not be stored in template map")
			}
		})
	}
}

func TestCollectingProcess_DecodeDataRecord(t *testing.T) {
	cp := CollectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16]*template)
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
	assert.Equal(t, ipAddress, sourceIPv4Address.GetIPAddressValue(), "sourceIPv4Address should be decoded and stored correctly.")
	// Malformed data record
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.decodePacket(bytes.NewBuffer(dataRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	clock := newFakeClock(time.Now())
	input := CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      udpTransport,
		MaxBufferSize: 1024,
		TemplateTTL:   1,
	}
	cp, err := initCollectingProcess(input, clock)
	require.NoError(t, err)
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
	template, err := cp.getTemplateIEs(1, 256)
	assert.NotNil(t, template, "Template should be stored in the template map.")
	assert.Nil(t, err, "Template should be stored in the template map.")
	clock.Step(time.Duration(input.TemplateTTL) * time.Second)
	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		_, err := cp.getTemplateIEs(1, 256)
		assert.ErrorContains(t, err, "does not exist", "template should be deleted after timeout")
	}, 1*time.Second, 50*time.Millisecond)
}

func TestUDPCollectingProcess_TemplateAddAndDelete(t *testing.T) {
	const (
		templateID  = 100
		obsDomainID = 0xabcd
	)
	clock := newFakeClock(time.Now())
	input := CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      udpTransport,
		MaxBufferSize: 1024,
		TemplateTTL:   1,
	}
	cp, err := initCollectingProcess(input, clock)
	require.NoError(t, err)
	cp.addTemplate(obsDomainID, templateID, elementsWithValueIPv4)
	// Get a copy of the stored template
	tpl := func() template {
		cp.mutex.RLock()
		defer cp.mutex.RUnlock()
		return *cp.templatesMap[obsDomainID][templateID]
	}()
	require.NotNil(t, tpl.expiryTimer)
	require.True(t, cp.deleteTemplate(obsDomainID, templateID))
	// Stop returns false if the timer has already been stopped, which
	// should be done by the call to deleteTemplate.
	assert.False(t, tpl.expiryTimer.Stop())
	// Deleting the template a second time should return false
	assert.False(t, cp.deleteTemplate(obsDomainID, templateID))
}

// TestUDPCollectingProcess_TemplateUpdate checks the behavior of addTemplate
// when a template is refreshed.
func TestUDPCollectingProcess_TemplateUpdate(t *testing.T) {
	const (
		templateID  = 100
		obsDomainID = 0xabcd
	)
	now := time.Now()
	clock := newFakeClock(now)
	input := CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      udpTransport,
		MaxBufferSize: 1024,
		TemplateTTL:   1,
	}
	cp, err := initCollectingProcess(input, clock)
	require.NoError(t, err)
	cp.addTemplate(obsDomainID, templateID, elementsWithValueIPv4)
	// Get a copy of the stored template
	getTemplate := func() template {
		cp.mutex.RLock()
		defer cp.mutex.RUnlock()
		return *cp.templatesMap[obsDomainID][templateID]
	}
	tpl := getTemplate()
	require.NotNil(t, tpl.expiryTimer)
	assert.Equal(t, now.Add(time.Duration(input.TemplateTTL)*time.Second), tpl.expiryTime)
	// Advance the clock by half the TTL
	clock.Step(500 * time.Millisecond)
	// Template should still be present in map
	_, err = cp.getTemplateIEs(obsDomainID, templateID)
	require.NoError(t, err)
	// "Update" the template (template is being refreshed)
	cp.addTemplate(obsDomainID, templateID, elementsWithValueIPv4)
	tpl = getTemplate()
	assert.Equal(t, clock.Now().Add(time.Duration(input.TemplateTTL)*time.Second), tpl.expiryTime)
	// Advance the clock by half the TTL again, template should still be present
	clock.Step(500 * time.Millisecond)
	_, err = cp.getTemplateIEs(obsDomainID, templateID)
	require.NoError(t, err)
	// Advance the clock by half the TTL again, template should be expired
	clock.Step(500 * time.Millisecond)
	_, err = cp.getTemplateIEs(obsDomainID, templateID)
	assert.Error(t, err)
}

func BenchmarkAddTemplateUDP(b *testing.B) {
	input := CollectorInput{
		Address:       hostPortIPv4,
		Protocol:      udpTransport,
		MaxBufferSize: 1024,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := initCollectingProcess(input, newFakeClock(time.Now()))
	require.NoError(b, err)
	obsDomainID := uint32(1)
	b.ResetTimer()
	for range b.N {
		cp.addTemplate(obsDomainID, 256, elementsWithValueIPv4)
		obsDomainID = (obsDomainID + 1) % 1000
	}
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
		ok := roots.AppendCertsFromPEM([]byte(testcerts.FakeCACert))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		cert, err := tls.X509KeyPair([]byte(testcerts.FakeClientCert), []byte(testcerts.FakeClientKey))
		if err != nil {
			t.Error(err)
		}
		config = &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
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
		ok := roots.AppendCertsFromPEM([]byte(testcerts.FakeCert2))
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
	template, _ := cp.getTemplateIEs(1, 256)
	assert.NotNil(t, template)
	ie, _, exist := message.GetSet().GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.True(t, exist)
	assert.Equal(t, net.ParseIP("2001:0:3238:DFE1:63::FEFB"), ie.GetIPAddressValue())
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
	template, _ := cp.getTemplateIEs(1, 256)
	assert.NotNil(t, template)
	ie, _, exist := message.GetSet().GetRecords()[0].GetInfoElementWithValue("sourceIPv6Address")
	assert.True(t, exist)
	assert.Equal(t, net.ParseIP("2001:0:3238:DFE1:63::FEFB"), ie.GetIPAddressValue())
}

// TestUnknownInformationElement validates that message decoding when dealing with unknown IEs (not
// part of the static registry included in this project). All 3 supported decoding modes are tested.
func TestUnknownInformationElement(t *testing.T) {
	const (
		templateID   = 100
		obsDomainID  = 0xabcd
		unknownID    = 999
		unknownValue = uint32(0x1234)
	)

	for _, enterpriseID := range []uint32{registry.IANAEnterpriseID, registry.AntreaEnterpriseID} {
		for _, mode := range []DecodingMode{DecodingModeStrict, DecodingModeLenientKeepUnknown, DecodingModeLenientDropUnknown} {
			t.Run(fmt.Sprintf("enterpriseID-%d_%s", enterpriseID, mode), func(t *testing.T) {
				input := getCollectorInput(tcpTransport, false, false)
				input.DecodingMode = mode
				cp, err := InitCollectingProcess(input)
				require.NoError(t, err)
				defer cp.Stop()

				go func() { // remove the message from the message channel
					for range cp.GetMsgChan() {
					}
				}()

				// First, send template set.

				unknownIE := entities.NewInfoElement("foo", unknownID, entities.Unsigned32, enterpriseID, 4)
				knownIE1, _ := registry.GetInfoElement("octetDeltaCount", registry.IANAEnterpriseID)
				knownIE2, _ := registry.GetInfoElement("sourceNodeName", registry.AntreaEnterpriseID)
				templateSet, err := entities.MakeTemplateSet(templateID, []*entities.InfoElement{knownIE1, unknownIE, knownIE2})
				require.NoError(t, err)
				templateBytes, err := exporter.CreateIPFIXMsg(templateSet, obsDomainID, 0 /* seqNumber */, time.Now())
				require.NoError(t, err)
				_, err = cp.decodePacket(bytes.NewBuffer(templateBytes), "1.2.3.4:12345")
				// If decoding is strict, there will be an error and we need to stop the test.
				if mode == DecodingModeStrict {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				// Second, send data set.

				unknownIEWithValue := entities.NewUnsigned32InfoElement(unknownIE, unknownValue)
				knownIE1WithValue := entities.NewUnsigned64InfoElement(knownIE1, 0x100)
				knownIE2WithValue := entities.NewStringInfoElement(knownIE2, "node-1")
				dataSet, err := entities.MakeDataSet(templateID, []entities.InfoElementWithValue{knownIE1WithValue, unknownIEWithValue, knownIE2WithValue})
				require.NoError(t, err)
				dataBytes, err := exporter.CreateIPFIXMsg(dataSet, obsDomainID, 1 /* seqNumber */, time.Now())
				require.NoError(t, err)
				msg, err := cp.decodePacket(bytes.NewBuffer(dataBytes), "1.2.3.4:12345")
				require.NoError(t, err)
				records := msg.GetSet().GetRecords()
				require.Len(t, records, 1)
				record := records[0]
				ies := record.GetOrderedElementList()

				if mode == DecodingModeLenientKeepUnknown {
					require.Len(t, ies, 3)
					// the unknown IE after decoding
					ieWithValue := ies[1]
					// the decoded IE has no name and the type always defaults to OctetArray
					require.Equal(t, entities.NewInfoElement("", unknownID, entities.OctetArray, enterpriseID, 4), ieWithValue.GetInfoElement())
					value := ieWithValue.GetOctetArrayValue()
					assert.Equal(t, unknownValue, binary.BigEndian.Uint32(value))
				} else if mode == DecodingModeLenientDropUnknown {
					require.Len(t, ies, 2)
				}
			})
		}
	}
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
				CACert:        []byte(testcerts.FakeCACert),
				ServerCert:    []byte(testcerts.FakeCert),
				ServerKey:     []byte(testcerts.FakeKey),
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
				ServerCert:    []byte(testcerts.FakeCert2),
				ServerKey:     []byte(testcerts.FakeKey2),
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
	checkConn := func(ctx context.Context) (bool, error) {
		if conn, err := net.Dial(cp.GetAddress().Network(), cp.GetAddress().String()); err != nil {
			return false, err
		} else {
			defer conn.Close()
			return true, nil
		}
	}
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 500*time.Millisecond, false, checkConn); err != nil {
		t.Errorf("Cannot establish connection to %s", cp.GetAddress().String())
	}
}
