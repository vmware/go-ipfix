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

package test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func TestUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, t)
}

func TestTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, t)
}

func TestMultipleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4738")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, t)
}

func TestMultipleRecordTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4738")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, t)
}

func testExporterToCollector(address net.Addr, isMultipleRecord bool, t *testing.T) {
	// Load the global registry
	registry.LoadRegistry()
	// Initialize collecting process
	cp, _ := collector.InitCollectingProcess(address, 1024, 0)

	go func() { // Start exporting process in go routine
		time.Sleep(2 * time.Second) // wait for collector to be ready
		export, err := exporter.InitExportingProcess(address, 1, 0)
		if err != nil {
			klog.Fatalf("Got error when connecting to %s", address.String())
		}

		// Create template record with 4 fields
		templateID := export.NewTemplateID()
		tempRec := entities.NewTemplateRecord(4, templateID)
		tempRec.PrepareRecord()
		element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		tempRec.AddInfoElement(element, nil, false)

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		tempRec.AddInfoElement(element, nil, false)

		element, err = registry.GetInfoElement("octetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		tempRec.AddInfoElement(element, nil, false)

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		tempRec.AddInfoElement(element, nil, false)

		// Send template record
		_, err = export.AddRecordAndSendMsg(entities.Template, tempRec)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
		// Create data set with 1 data record using the same template above
		dataSet := entities.NewDataSet()
		elements := make([]*entities.InfoElementValue, 0)
		element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		ieValue1 := entities.NewInfoElementValue(element, net.ParseIP("1.2.3.4"))

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		ieValue2 := entities.NewInfoElementValue(element, net.ParseIP("5.6.7.8"))

		element, err = registry.GetInfoElement("octetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		ieValue3 := entities.NewInfoElementValue(element, uint64(12345678))

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		ieValue4 := entities.NewInfoElementValue(element, "pod1")

		elements = append(elements, ieValue1, ieValue2, ieValue3, ieValue4)
		dataSet.AddRecord(elements, templateID, false)

		// for multiple records per set, modify element values and add another record to set
		if isMultipleRecord {
			ieValue1 := entities.NewInfoElementValue(elements[0].Element, net.ParseIP("4.3.2.1"))
			ieValue2 := entities.NewInfoElementValue(elements[1].Element, net.ParseIP("8.7.6.5"))
			ieValue3 := entities.NewInfoElementValue(elements[2].Element, uint64(0))
			ieValue4 := entities.NewInfoElementValue(elements[3].Element,"pod2")
			ieValues := make([]*entities.InfoElementValue, 0)
			ieValues = append(ieValues, ieValue1, ieValue2, ieValue3, ieValue4)
			dataSet.AddRecord(ieValues, templateID, false)
		}

		// Send data set
		_, err = export.AddRecordAndSendMsg(entities.Data, dataSet.GetRecords()...)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
		export.CloseConnToCollector() // Close exporting process
		time.Sleep(2 * time.Second)
		cp.Stop() // Close collecting process
	}()

	// Start collecting process
	cp.Start()
	templateMsg := cp.GetMessages()[0]
	dataMsg := cp.GetMessages()[1]
	assert.Equal(t, uint16(10), templateMsg.Version, "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), templateMsg.ObsDomainID, "ObsDomainID (template) should be 1.")
	assert.Equal(t, uint16(10), dataMsg.Version, "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), dataMsg.ObsDomainID, "ObsDomainID (template) should be 1.")
	templateSet, ok := templateMsg.Set.(*entities.TemplateSet)
	if !ok {
		t.Error("Template packet is not decoded correctly.")
	}
	templateElements := templateSet.GetRecords()[0].GetTemplateElements()
	assert.Equal(t, uint32(0), templateElements[0].EnterpriseId, "Template record is not stored correctly.")

	dataSet, ok := dataMsg.Set.(*entities.DataSet)
	if !ok {
		t.Error("Data packet is not decoded correctly.")
	}
	dataElements := dataSet.GetRecords()[0].GetDataElements()
	assert.Equal(t, []byte{1, 2, 3, 4}, dataElements[0].Value, "DataSet does not store elements (IANA) correctly.")
	assert.Equal(t, uint64(12345678), dataElements[2].Value, "DataSet does not store reverse information elements (IANA) correctly.")
	assert.Equal(t, "pod1", dataElements[3].Value, "DataSet does not store elements (Antrea) correctly.")
	if isMultipleRecord {
		dataElements := dataSet.GetRecords()[1].GetDataElements()
		assert.Equal(t, []byte{4, 3, 2, 1}, dataElements[0].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, uint64(0), dataElements[2].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, "pod2", dataElements[3].Value, "DataSet does not store multiple records correctly.")
	}
}
