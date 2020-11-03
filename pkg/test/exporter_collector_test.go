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
	testExporterToCollector(address, t)
}

func TestTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, t)
}

func testExporterToCollector(address net.Addr, t *testing.T) {
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

		// Create template record with 5 fields
		templateID := export.NewTemplateID()
		tempRec := entities.NewTemplateRecord(5, templateID)
		tempRec.PrepareRecord()
		element, err := registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		tempRec.AddInfoElement(element, nil)

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		tempRec.AddInfoElement(element, nil)

		element, err = registry.GetInfoElement("reverseOctetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		tempRec.AddInfoElement(element, nil)

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		tempRec.AddInfoElement(element, nil)

		element, err = registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name flowStartSeconds")
		}
		tempRec.AddInfoElement(element, nil)

		// Send template record
		_, err = export.AddRecordAndSendMsg(entities.Template, tempRec)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
		// Create data record using the same template above
		dataRec := entities.NewDataRecord(templateID)
		dataRec.PrepareRecord()
		element, err = registry.GetInfoElement("sourceIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourceIPv4Address")
		}
		dataRec.AddInfoElement(element, net.ParseIP("1.2.3.4"))

		element, err = registry.GetInfoElement("destinationIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name destinationIPv4Address")
		}
		dataRec.AddInfoElement(element, net.ParseIP("5.6.7.8"))

		element, err = registry.GetInfoElement("reverseOctetDeltaCount", registry.IANAReversedEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the reverse element of octetDeltaCount")
		}
		dataRec.AddInfoElement(element, uint64(12345678))

		element, err = registry.GetInfoElement("sourcePodName", registry.AntreaEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name sourcePodName")
		}
		dataRec.AddInfoElement(element, "pod1")

		element, err = registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name flowStartSeconds")
		}
		dataRec.AddInfoElement(element, uint32(1257894000))

		// Send data record
		_, err = export.AddRecordAndSendMsg(entities.Data, dataRec)
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

	templateSet, ok := templateMsg.Set.(entities.TemplateSet)
	if !ok {
		t.Error("Template packet is not decoded correctly.")
	}
	assert.Equal(t, []uint16{8, 12, 150}, templateSet[registry.IANAEnterpriseID], "TemplateSet does not store template elements (IANA) correctly.")
	assert.Equal(t, []uint16{1}, templateSet[registry.IANAReversedEnterpriseID], "TemplateSet does not store template elements (reverse information element) correctly.")
	assert.Equal(t, []uint16{101}, templateSet[registry.AntreaEnterpriseID], "TemplateSet does not store template elements (Antrea) correctly.")

	dataSet, ok := dataMsg.Set.(entities.DataSet)
	if !ok {
		t.Error("Data packet is not decoded correctly.")
	}
	assert.Equal(t, []byte{1, 2, 3, 4}, dataSet[registry.IANAEnterpriseID][8], "DataSet does not store elements (IANA) correctly.")
	assert.Equal(t, uint32(1257894000), dataSet[registry.IANAEnterpriseID][150], "DataSet does not store elements (IANA) correctly.")
	assert.Equal(t, uint64(12345678), dataSet[registry.IANAReversedEnterpriseID][1], "DataSet does not store reverse information elements (IANA) correctly.")
	assert.Equal(t, "pod1", dataSet[registry.AntreaEnterpriseID][101], "DataSet does not store elements (Antrea) correctly.")
}
