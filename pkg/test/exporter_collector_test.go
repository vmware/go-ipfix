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

// +build integration

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

func TestSingleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, t)
}

func TestSingleRecordTCPTransport(t *testing.T) {
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
		templateSet := entities.NewSet(entities.Template, templateID, false)
		elements := make([]*entities.InfoElementWithValue, 0)
		element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		ie = entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("octetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		ie = entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		ie = entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
		templateSet.AddRecord(elements, templateID)

		// Send template record
		_, err = export.AddSetAndSendMsg(entities.Template, templateSet)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
		time.Sleep(time.Second)
		// Create data set with 1 data record using the same template above
		dataSet := entities.NewSet(entities.Data, templateID, false)
		elements = make([]*entities.InfoElementWithValue, 0)
		element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		ie = entities.NewInfoElementWithValue(element, net.ParseIP("1.2.3.4"))
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		ie = entities.NewInfoElementWithValue(element, net.ParseIP("5.6.7.8"))
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("octetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		ie = entities.NewInfoElementWithValue(element, uint64(12345678))
		elements = append(elements, ie)

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		ie = entities.NewInfoElementWithValue(element, "pod1")
		elements = append(elements, ie)

		dataSet.AddRecord(elements, templateID)
		// for multiple records per set, modify element values and add another record to set
		if isMultipleRecord {
			elements := make([]*entities.InfoElementWithValue, 0)
			element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
			if err != nil {
				klog.Errorf("Did not find the element with name sourceIPv4Address")
			}
			ie := entities.NewInfoElementWithValue(element, net.ParseIP("4.3.2.1"))
			elements = append(elements, ie)

			element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
			if err != nil {
				klog.Errorf("Did not find the element with name destinationIPv4Address")
			}
			ie = entities.NewInfoElementWithValue(element, net.ParseIP("8.7.6.5"))
			elements = append(elements, ie)

			element, err = registry.GetInfoElement("octetDeltaCount", registry.IANAReversedEnterpriseID)
			if err != nil {
				klog.Errorf("Did not find the reverse element of octetDeltaCount")
			}
			ie = entities.NewInfoElementWithValue(element, uint64(0))
			elements = append(elements, ie)

			element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
			if err != nil {
				klog.Errorf("Did not find the element with name sourcePodName")
			}
			ie = entities.NewInfoElementWithValue(element, "pod2")
			elements = append(elements, ie)

			dataSet.AddRecord(elements, templateID)
		}

		// Send data set
		_, err = export.AddSetAndSendMsg(entities.Data, dataSet)
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
	templateSet, ok := templateMsg.Set.(entities.Set)
	if !ok {
		t.Error("Template packet is not decoded correctly.")
	}
	templateElements := templateSet.GetRecords()[0].GetInfoElements()
	assert.Equal(t, uint32(0), templateElements[0].Element.EnterpriseId, "Template record is not stored correctly.")

	dataSet, ok := dataMsg.Set.(entities.Set)
	if !ok {
		t.Error("Data packet is not decoded correctly.")
	}
	dataElements := dataSet.GetRecords()[0].GetInfoElements()
	assert.Equal(t, []byte{1, 2, 3, 4}, dataElements[0].Value, "DataSet does not store elements (IANA) correctly.")
	assert.Equal(t, uint64(12345678), dataElements[2].Value, "DataSet does not store reverse information elements (IANA) correctly.")
	assert.Equal(t, "pod1", dataElements[3].Value, "DataSet does not store elements (Antrea) correctly.")
	if isMultipleRecord {
		dataElements := dataSet.GetRecords()[1].GetInfoElements()
		assert.Equal(t, []byte{4, 3, 2, 1}, dataElements[0].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, uint64(0), dataElements[2].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, "pod2", dataElements[3].Value, "DataSet does not store multiple records correctly.")
	}
}
