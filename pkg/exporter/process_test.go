// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package exporter

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func TestExportingProcess_SendingTemplateRecordToLocalTCPServer(t *testing.T) {
	// Create local server for testing
	listener, err := net.Listen("tcp", ":0")
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
			t.Fatal(err)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(listener.Addr(), 1, 0)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())

	// Add template to exporting process
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	tempRec := entities.NewTemplateRecord(2, templateID)
	tempRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	tempRecBuff := tempRec.GetBuffer()
	tempRecBytes := tempRecBuff.Bytes()


	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Template, tempRec)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, tempRecBytes, <-buffCh)
	assert.Equal(t, uint32(0), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingTemplateRecordToLocalUDPServer(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
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
		for start := time.Now(); time.Since(start) < 2* time.Second; {
			b := make([]byte, 32)
			nb, err := conn.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			numBytes = numBytes + nb
			bytes = append(bytes, b...)
		}
		// Compare only template record part. Remove message header and set header.
		buffCh <- bytes
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(conn.LocalAddr(), 1, 2)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())

	// Add template to exporting process
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	tempRec := entities.NewTemplateRecord(2, templateID)
	tempRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	tempRec.AddInfoElement(element, nil)
	tempRecBuff := tempRec.GetBuffer()
	tempRecBytes := tempRecBuff.Bytes()

	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Template, tempRec)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// Sleep for 2s for template refresh routine to get executed
	time.Sleep(2 * time.Second)

	// Expect to receive two template headers one from AddRecordAndSendMsg and other from tempRefresh go routine
	bytesAtServer := <-buffCh
	assert.Equal(t, len(bytesAtServer), 64)
	assert.Equal(t, bytesAtServer[20:32], bytesAtServer[52:], "both template messages should be same")
	firstTemplateBytes := bytesAtServer[:32]
	// 32 is the size of the IPFIX message including all headers
	assert.Equal(t, 32, bytesSent)
	assert.Equal(t, tempRecBytes, firstTemplateBytes[20:])
	assert.Equal(t, uint32(0), exporter.seqNumber)

	exporter.CloseConnToCollector()

}

func TestExportingProcess_SendingDataRecordToLocalTCPServer(t *testing.T) {
	// Create local server for testing
	listener, err := net.Listen("tcp", ":0")
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
			t.Fatal(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(listener.Addr(), 1, 0)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", listener.Addr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", listener.Addr().String())

	// Add data to exporting process
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()

	// [Only for testing] Ensure corresponding template exists in the exporting process before sending data
	templateID := exporter.NewTemplateID()
	// Get the element to update template in exporting process
	element1, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	element2, err := reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	// Hardcoding 8-bytes min data record length for testing purposes instead of creating template record
	exporter.updateTemplate(templateID, []*entities.InfoElement{element1, element2}, 8)

	// Create data record with two fields
	dataRec := entities.NewDataRecord(templateID)
	dataRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("1.2.3.4"))

	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("5.6.7.8"))
	dataRecBuff := dataRec.GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()

	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Data, dataRec)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)
	exporter.CloseConnToCollector()
}

func TestExportingProcess_SendingDataRecordToLocalUDPServer(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("Got error when resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	t.Log("Created local server on random available port for testing")

	buffCh := make(chan []byte)
	// Create go routine for local server
	// TODO: Move this in to different function with byte size as arg
	go func() {
		defer conn.Close()
		buff := make([]byte, 28)
		_, err = conn.Read(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Compare only data record part. Remove message header and set header.
		// TODO: Verify message header and set header through hardcoded byte values
		buffCh <- buff[20:]
		return
	}()

	// Create exporter using local server info
	exporter, err := InitExportingProcess(conn.LocalAddr(), 1, 0)
	if err != nil {
		t.Fatalf("Got error when connecting to local server %s: %v", conn.LocalAddr().String(), err)
	}
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())

	// Add data to exporting process
	reg := registry.NewIanaRegistry()
	reg.LoadRegistry()
	// [Only for testing] Ensure corresponding template exists in the exporting process before sending data
	templateID := exporter.NewTemplateID()
	// Get the element to update template in exporting process
	element1, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	element2, err := reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	// Hardcoding 8-bytes min data record length for testing purposes instead of creating template record
	exporter.updateTemplate(templateID, []*entities.InfoElement{element1, element2}, 8)


	// Create data record with two fields
	dataRec := entities.NewDataRecord(templateID)
	dataRec.PrepareRecord()
	element, err := reg.GetInfoElement("sourceIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name sourceIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("1.2.3.4"))

	element, err = reg.GetInfoElement("destinationIPv4Address")
	if err != nil {
		t.Errorf("Did not find the element with name destinationIPv4Address")
	}
	dataRec.AddInfoElement(element, net.ParseIP("5.6.7.8"))
	dataRecBuff := dataRec.GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()
	bytesSent, err := exporter.AddRecordAndSendMsg(entities.Data, dataRec)
	if err != nil {
		t.Fatalf("Got error when sending record: %v", err)
	}
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)
	exporter.CloseConnToCollector()
}
