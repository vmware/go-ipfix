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

package exporter

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/test"
)

func init() {
	registry.LoadRegistry()
}

func TestExportingProcess_SendingTemplateRecordToLocalTCPServer(t *testing.T) {
	// Create local server for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 32)
		_, err = conn.Read(buff)
		if err != nil {
			t.Error(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    listener.Addr().String(),
		CollectorProtocol:   listener.Addr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		PathMTU:             0,
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err = templateSet.PrepareSet(entities.Template, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	templateSet.AddRecord(elements, 0, templateID)

	bytesSent, err := exporter.SendSet(templateSet)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingTemplateRecordToLocalUDPServer(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer conn.Close()

		bytes := make([]byte, 0)
		numBytes := 0
		// Wait for template refresh timeout to receive both messages.
		for start := time.Now(); time.Since(start) < 1*time.Second; {
			b := make([]byte, 32)
			nb, err := conn.Read(b)
			if err != nil {
				t.Error(err)
			}
			numBytes = numBytes + nb
			bytes = append(bytes, b...)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- bytes
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      1,
		PathMTU:             0,
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err = templateSet.PrepareSet(entities.Template, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)

	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)

	templateSet.AddRecord(elements, 0, templateID)

	bytesSent, err := exporter.SendSet(templateSet)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// Expect to receive two template headers one that was sent initially and other
	// from tempRefresh go routine.
	bytesAtServer := <-buffCh
	assert.Equal(t, len(bytesAtServer), 64)
	assert.Equal(t, bytesAtServer[20:32], bytesAtServer[52:], "both template messages should be same")
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, uint32(0), exporter.seqNumber)

	exporter.CloseConnToCollector()

}

func TestExportingProcess_SendingDataRecordToLocalTCPServer(t *testing.T) {
	// Create local server for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 28)
		_, err = conn.Read(buff)
		if err != nil {
			t.Error(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    listener.Addr().String(),
		CollectorProtocol:   listener.Addr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		PathMTU:             0,
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())

	// [Only for testing] Ensure corresponding template exists in the exporting process before sending data
	templateID := exporter.NewTemplateID()
	// Get the element to update template in exporting process
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	element1 := entities.NewInfoElementWithValue(element, nil)
	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	element2 := entities.NewInfoElementWithValue(element, nil)
	// Hardcoding 8-bytes min data record length for testing purposes instead of creating template record
	exporter.updateTemplate(templateID, []entities.InfoElementWithValue{element1, element2}, 8)

	// Create data set with 1 data record
	dataSet := entities.NewSet(false)
	err = dataSet.PrepareSet(entities.Data, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, net.ParseIP("1.2.3.4"))
	elements = append(elements, ie)

	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, net.ParseIP("5.6.7.8"))
	elements = append(elements, ie)

	dataSet.AddRecord(elements, 0, templateID)
	dataRecBuff := dataSet.GetRecords()[0].GetBuffer()

	bytesSent, err := exporter.SendSet(dataSet)
	assert.NoError(t, err)
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBuff, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)

	// Create data set with multiple data records to test invalid message length
	// logic for TCP transport.
	dataSet.ResetSet()
	err = dataSet.PrepareSet(entities.Data, templateID)
	assert.NoError(t, err)
	for i := 0; i < 10000; i++ {
		err := dataSet.AddRecord(elements, 0, templateID)
		assert.NoError(t, err)
	}
	_, err = exporter.SendSet(dataSet)
	assert.Error(t, err)

	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingDataRecordToLocalUDPServer(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, _ := net.ListenUDP("udp", udpAddr)
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)

	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer conn.Close()
		buff := make([]byte, 28)
		_, err := conn.Read(buff)
		if err != nil {
			t.Error(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		PathMTU:             0,
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())

	// [Only for testing] Ensure corresponding template exists in the exporting process before sending data
	templateID := exporter.NewTemplateID()
	// Get the element to update template in exporting process
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	element1 := entities.NewInfoElementWithValue(element, nil)
	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	element2 := entities.NewInfoElementWithValue(element, nil)
	// Hardcoding 8-bytes min data record length for testing purposes instead of creating template record
	exporter.updateTemplate(templateID, []entities.InfoElementWithValue{element1, element2}, 8)

	// Create data set with 1 data record
	dataSet := entities.NewSet(false)
	err = dataSet.PrepareSet(entities.Data, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, net.ParseIP("1.2.3.4"))
	elements = append(elements, ie)

	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, net.ParseIP("5.6.7.8"))
	elements = append(elements, ie)

	dataSet.AddRecord(elements, 0, templateID)
	dataRecBuff := dataSet.GetRecords()[0].GetBuffer()

	bytesSent, err := exporter.SendSet(dataSet)
	assert.NoError(t, err)
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBuff, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)

	// Create data set with multiple data records to test invalid message length
	// logic for UDP transport.
	dataSet.ResetSet()
	err = dataSet.PrepareSet(entities.Data, templateID)
	assert.NoError(t, err)
	for i := 0; i < 100; i++ {
		dataSet.AddRecord(elements, 0, templateID)
	}
	_, err = exporter.SendSet(dataSet)
	assert.Error(t, err)

	exporter.CloseConnToCollector()
}

func TestExportingProcessWithTLS(t *testing.T) {
	// Create local server for testing
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when resolving tcp address: %v", err)
	}
	cer, err := tls.X509KeyPair([]byte(test.FakeCert), []byte(test.FakeKey))
	if err != nil {
		t.Error(err)
		return
	}
	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	listener, err := tls.Listen("tcp", address.String(), config)
	if err != nil {
		t.Errorf("Cannot start tls collecting process on %s: %v", listener.Addr().String(), err)
		return
	}

	buffCh := make(chan []byte)
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 32)
		_, err = conn.Read(buff)
		if err != nil {
			t.Error(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    listener.Addr().String(),
		CollectorProtocol:   listener.Addr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		IsEncrypted:         true,
		CACert:              []byte(test.FakeCACert),
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local tls server %s: %v", listener.Addr(), err)
	}
	t.Logf("Created exporter connecting to local tls server with address: %s", listener.Addr())

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err = templateSet.PrepareSet(entities.Template, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	templateSet.AddRecord(elements, 0, templateID)

	bytesSent, err := exporter.SendSet(templateSet)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcessWithDTLS(t *testing.T) {
	// Create local server for testing
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when resolving udp address: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(test.FakeCert2), []byte(test.FakeKey2))
	if err != nil {
		t.Error(err)
		return
	}
	config := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}
	listener, err := dtls.Listen("udp", address, config)
	if err != nil {
		t.Errorf("Cannot start dtls collecting process on %s: %v", listener.Addr().String(), err)
		return
	}

	buffCh := make(chan []byte)
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Log("Accept the connection from exporter")
		buff := make([]byte, 32)
		_, err = conn.Read(buff)
		if err != nil {
			t.Error(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    listener.Addr().String(),
		CollectorProtocol:   listener.Addr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		IsEncrypted:         true,
		CACert:              []byte(test.FakeCert2),
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local dtls server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local dtls server with address: %s", listener.Addr().String())

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(false)
	err = templateSet.PrepareSet(entities.Template, templateID)
	assert.NoError(t, err)
	elements := make([]entities.InfoElementWithValue, 0)
	element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	ie := entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	ie = entities.NewInfoElementWithValue(element, nil)
	elements = append(elements, ie)
	templateSet.AddRecord(elements, 0, templateID)

	bytesSent, err := exporter.SendSet(templateSet)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_GetMsgSizeLimit(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	t.Log("Created local server on random available port for testing")
	defer conn.Close()
	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		TempRefTimeout:      1,
		PathMTU:             0,
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	assert.Equal(t, entities.DefaultUDPMsgSize, exporter.GetMsgSizeLimit())
}

func TestExportingProcess_CheckConnToCollector(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Got error when creating a local server: %v", err)
	}
	input := ExporterInput{
		CollectorAddress:  listener.Addr().String(),
		CollectorProtocol: listener.Addr().Network(),
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}

	defer listener.Close()
	conn, _ := listener.Accept()
	oneByte := make([]byte, 1)
	isOpen := exporter.checkConnToCollector(oneByte)
	assert.True(t, isOpen)
	conn.Close()
	isOpen = exporter.checkConnToCollector(oneByte)
	assert.False(t, isOpen)
}
