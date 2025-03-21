// Copyright 2025 VMware, Inc.
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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func TestBufferedExporter(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	t.Log("Created local server on random available port for testing")

	receivedLengthsCh := make(chan int, 10)
	go func() {
		defer conn.Close()
		b := make([]byte, 512)
		for {
			n, err := conn.Read(b)
			if err != nil {
				return
			}
			receivedLengthsCh <- n
		}
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		MaxMsgSize:          512,
	}
	exporter, err := InitExportingProcess(input)
	require.NoError(t, err)
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	defer exporter.CloseConnToCollector()

	bufferedExporter := NewBufferedIPFIXExporter(exporter)

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	elements := make([]entities.InfoElementWithValue, 0)
	ieSrc, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	require.NoError(t, err, "Did not find the element with name sourceIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieSrc, nil))
	ieDst, err := registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	require.NoError(t, err, "Did not find the element with name destinationIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieDst, nil))
	template := entities.NewTemplateRecordFromElements(templateID, elements)
	require.NoError(t, template.PrepareRecord())

	require.NoError(t, bufferedExporter.AddRecord(template))
	select {
	case <-receivedLengthsCh:
		break
	case <-time.After(100 * time.Millisecond):
		require.Fail(t, "Expected template not received")
	}

	record := func() entities.Record {
		elements := []entities.InfoElementWithValue{
			entities.NewIPAddressInfoElement(ieSrc, net.ParseIP("1.2.3.4")),
			entities.NewIPAddressInfoElement(ieDst, net.ParseIP("5.6.7.8")),
		}
		return entities.NewDataRecordFromElements(templateID, elements)
	}()
	// Each record will be 8B. The message size has been set to 512B above.
	// The overhead per message is 16 (message header) + 4 (set header).
	// So we can fit 61 records per message.
	// If we send 200 records, we will need 4 messages.
	for range 200 {
		require.Equal(t, 8, record.GetRecordLength()) // sanity check
		require.NoError(t, bufferedExporter.AddRecord(record))
	}
	require.NoError(t, bufferedExporter.Flush())

	timerCh := time.After(100 * time.Millisecond)
	for _, expectedBytesReceived := range []int{508, 508, 508, 156} {
		select {
		case bytesReceived := <-receivedLengthsCh:
			assert.Equal(t, expectedBytesReceived, bytesReceived)
		case <-timerCh:
			require.Fail(t, "Expected message not received")
		}
	}
}

func BenchmarkBufferedExporter(b *testing.B) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(b, err)
	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(b, err)

	go func() {
		defer conn.Close()
		b := make([]byte, 512)
		for {
			if _, err := conn.Read(b); err != nil {
				return
			}
		}
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		MaxMsgSize:          512,
	}
	exporter, err := InitExportingProcess(input)
	require.NoError(b, err)
	b.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	defer exporter.CloseConnToCollector()

	bufferedExporter := NewBufferedIPFIXExporter(exporter)

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	elements := make([]entities.InfoElementWithValue, 0)
	ieSrc, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	require.NoError(b, err, "Did not find the element with name sourceIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieSrc, nil))
	ieDst, err := registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	require.NoError(b, err, "Did not find the element with name destinationIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieDst, nil))
	template := entities.NewTemplateRecordFromElements(templateID, elements)
	require.NoError(b, template.PrepareRecord())

	require.NoError(b, bufferedExporter.AddRecord(template))

	record := func() entities.Record {
		elements := []entities.InfoElementWithValue{
			entities.NewIPAddressInfoElement(ieSrc, net.ParseIP("1.2.3.4")),
			entities.NewIPAddressInfoElement(ieDst, net.ParseIP("5.6.7.8")),
		}
		return entities.NewDataRecordFromElements(templateID, elements)
	}()

	b.ResetTimer()

	for range b.N {
		require.NoError(b, bufferedExporter.AddRecord(record))
	}
}

func TestBufferedExporter_UpdateTemplate(t *testing.T) {
	// Create local server for testing
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", udpAddr)
	require.NoError(t, err)
	t.Log("Created local server on random available port for testing")

	receivedLengthsCh := make(chan int, 10)
	go func() {
		defer conn.Close()
		b := make([]byte, 512)
		for {
			n, err := conn.Read(b)
			if err != nil {
				return
			}
			receivedLengthsCh <- n
		}
	}()

	// Create exporter using local server info
	input := ExporterInput{
		CollectorAddress:    conn.LocalAddr().String(),
		CollectorProtocol:   conn.LocalAddr().Network(),
		ObservationDomainID: 1,
		MaxMsgSize:          512,
	}
	exporter, err := InitExportingProcess(input)
	require.NoError(t, err)
	t.Logf("Created exporter connecting to local server with address: %s", conn.LocalAddr().String())
	defer exporter.CloseConnToCollector()

	bufferedExporter := NewBufferedIPFIXExporter(exporter)

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	elements := make([]entities.InfoElementWithValue, 0)
	ieSrc, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
	require.NoError(t, err, "Did not find the element with name sourceIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieSrc, nil))
	ieDst, err := registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
	require.NoError(t, err, "Did not find the element with name destinationIPv4Address")
	elements = append(elements, entities.NewIPAddressInfoElement(ieDst, nil))
	template := entities.NewTemplateRecordFromElements(templateID, elements)
	require.NoError(t, template.PrepareRecord())

	// msg header (16) + set header (4) + template record header (4) + 2 field specifiers (8)
	const templateMsgLength = 16 + 4 + 4 + 8
	// msg header (16) + set header (4) + 2 field values (8)
	const dataMsgLength = 16 + 4 + 8

	expectTemplate := func(t *testing.T) {
		t.Helper()
		select {
		case x := <-receivedLengthsCh:
			require.Equal(t, templateMsgLength, x)
		case <-time.After(100 * time.Millisecond):
			require.Fail(t, "Expected template not received")
		}
	}

	expectData := func(t *testing.T) {
		t.Helper()
		select {
		case x := <-receivedLengthsCh:
			require.Equal(t, dataMsgLength, x)
		case <-time.After(100 * time.Millisecond):
			require.Fail(t, "Expected data not received")
		}
	}

	expectNothing := func(t *testing.T) {
		t.Helper()
		select {
		case <-receivedLengthsCh:
			require.Fail(t, "No IPFIX message should have been exported")
		case <-time.After(100 * time.Millisecond):
			break
		}
	}

	require.NoError(t, bufferedExporter.AddRecord(template))
	expectTemplate(t)

	record := func() entities.Record {
		elements := []entities.InfoElementWithValue{
			entities.NewIPAddressInfoElement(ieSrc, net.ParseIP("1.2.3.4")),
			entities.NewIPAddressInfoElement(ieDst, net.ParseIP("5.6.7.8")),
		}
		return entities.NewDataRecordFromElements(templateID, elements)
	}()

	require.NoError(t, bufferedExporter.AddRecord(record))
	expectNothing(t)

	require.NoError(t, bufferedExporter.AddRecord(template))
	expectData(t)
	expectTemplate(t)

	require.NoError(t, bufferedExporter.AddRecord(record))
	expectNothing(t)
	require.NoError(t, bufferedExporter.Flush())
	expectData(t)
}
