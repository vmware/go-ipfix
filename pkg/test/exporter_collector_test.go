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

	"github.com/stretchr/testify/assert"
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"
)

func init() {
	// Load the global registry
	registry.LoadRegistry()
}

const (
	fakeKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDz3PD8TwjDfQg2
IiBVZMZT1RJLZwZZXWYkukWfhx7Zp1iJeAX1ExSEcnq1b9Hc1cP0PXsw0eoqXomH
tAimX/k0d6IqLHTiB7fFJF2cuAjQbMBoGxN5v+0elJOBCwAaY8E0iwPwuKa4VFua
6rSqSfkhQ4FQqaUqhy6eqp3vD/ycHhje1VX3S66hwGMaDLi2trnm88fjm81I1A0d
bwPRPO0246m2loG7xB8RYfMLgCLzhOQLz2Uow0HfjbJQ+IlDQ3uuWdzr46nqQaes
T6ULLz8N560+rjQD0Dg3GGeqaHEP7OaLmVQBqtsj0GroD7xscDKkgq9fnW9VuGjZ
2tKElip5AgMBAAECggEBAO/NrnSOS7Hg+/gvqtgOVzEM8AaR8x5hyBYJznlHaEDk
XR4hlsoezyhHYv+UTCz7UMyWwNOLONgdSuTVV0Q0UF0V37PVL8Mtj7sfPablGlXK
+5HkPkyVPVm7BSn6ZUmOGunOYjuPePL+kW5PqwVh5MifF0T47eBaOq/wW4pAkEn7
KzHcVEy08VnaK3XIC7lS9f5o/L9KSlZQU15TUAjFZ/kn4phzsR/z5462qKl9obYQ
gOqtK5ZA4ZqTX0nbzaqM20rhZEv+FkDWmSzcAaGfjvPtjFUmrChhpVSRqtcxlgEK
qwVM01i8t/E8p0Y4/2+GSDs4yKFeJNVuQ9AsLdhpJRkCgYEA//C+d/ltVhQtKaoA
dJy+AESTaVWS5IUmcE2x4fu9vyDR/U6FyPUmU4imwO4wS0O8jLdExjtb2kaIiGth
b3cmoUe77Xpi+iLSIAVk27QYWlnAQY/VkAZZZtY3JS75jdo4TShiafYq4vb0Gux7
jDkh+VW2mTRpp0if88y/61HPH8cCgYEA8+t6ON3CY3U19wtoQEA01kLk13B182ps
7beRidxW37ndOVXGj27xeEuzHlj/ry+kh+AOkHRbiz1RvhdX2POotgwX0Tdq/SXv
CIYsL02ZS1m33GwrvoVfsTOpvKrQMlX7WpXYpghagf2y6TEJiCtWlSROJhje9K2I
eL5jwV8g478CgYEAiYNEExoE0NcOXPBmRkFhJKuzuEiuH/IacQSNqqmjjWmI6dyi
rRJqgT9OuSJA+G9wgvqFDS0fcOust/9Z3pXaP5VXN4UmYNcMpv++7PyaiRDn51Hs
oPGIX2SBRI00sC6rSWmFVwFYkZG2HjEpQHIB+wE+lpo+mg6/QjKkez79VkkCgYAP
BnFX8WkZAU5asmwwkQPwMtyv3LCXVvXwyr7/VABR9bwH3R3HFhlvxJH7C5Zsby3e
ZNHg2hoNgLB5WizCI3hABoytCZHgmCaaStGL9Ga9+n/V5x/ms4aKftk00vzSLPO3
x8U5rQgOO9d6f9fLeIfz1fGubRfG0K24alnwvnBjNwKBgDtu5OUrOtAW4pZVj5rs
YK1g7EZMreBtU1ox80vhU7QT707EI2LfI7J9MGfEHcstjl868Z8JBIyjyEmAJxYv
08oooxSfn83rnXzn+XFaQKSuAYzbQXulKh3DGucZY1n8tPT9I+jbtGvGBj94FuBQ
SuTFwBux90EAGPE4SyuCHgYo
-----END PRIVATE KEY-----
`
	fakeCert = `-----BEGIN CERTIFICATE-----
MIIDhjCCAm6gAwIBAgIJAJPXwf3JizlIMA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNV
BAYTAlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcMA04vQTEgMB4GA1UECgwXU2Vs
Zi1zaWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMMIjEyMC4wLjAuMTogU2VsZi1z
aWduZWQgY2VydGlmaWNhdGUwHhcNMjAxMjAxMDQyNjA0WhcNMjIxMjAxMDQyNjA0
WjB4MQswCQYDVQQGEwJYWDEMMAoGA1UECAwDTi9BMQwwCgYDVQQHDANOL0ExIDAe
BgNVBAoMF1NlbGYtc2lnbmVkIGNlcnRpZmljYXRlMSswKQYDVQQDDCIxMjAuMC4w
LjE6IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA89zw/E8Iw30INiIgVWTGU9USS2cGWV1mJLpFn4ce2adYiXgF
9RMUhHJ6tW/R3NXD9D17MNHqKl6Jh7QIpl/5NHeiKix04ge3xSRdnLgI0GzAaBsT
eb/tHpSTgQsAGmPBNIsD8LimuFRbmuq0qkn5IUOBUKmlKocunqqd7w/8nB4Y3tVV
90uuocBjGgy4tra55vPH45vNSNQNHW8D0TztNuOptpaBu8QfEWHzC4Ai84TkC89l
KMNB342yUPiJQ0N7rlnc6+Op6kGnrE+lCy8/DeetPq40A9A4NxhnqmhxD+zmi5lU
AarbI9Bq6A+8bHAypIKvX51vVbho2drShJYqeQIDAQABoxMwETAPBgNVHREECDAG
hwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQBninXJdEqqsJtqJKwog5X/EY7+Qgxh
f4Ye7cI3JvGuH1InmZkLmgJAtRy5MDo64GZmPjKJsr4a5M+DARFcRnoFhqo7uXoS
M3D5l9hbUUrXDrQzTww+6ga2wwZEFaOkzNLaTZ2bw01vVM3Xpqn5y0N4+7fTw6Ka
M2xhaFYgJzDy9nQjmTn2F3G8s27xQ3ebAy/KcNGJJwf3vFC76i76sa78jWYmGOO2
hyHgFXOE2+9q4J364PTipSwLgFr7lz4CF+OCzttpyFqB34c54atCQ7ste/NXysIO
F90n06ISWkonCXiZ09r3ooH5py6GBFf15ZKrBzetZN+aSJcBjHXasQrA
-----END CERTIFICATE-----
`
	fakeKey2 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnOocXNDRcH6BZ86v
4GwZF6JiqYbF7bxrssfJ/Ge0jbihRANCAARX5PJ6Za+ZkYvliOtKO2fCbJG07/Pw
nrBDHZzPbrdW0TJNZ9psQjj0dgG15/Jimn1YnnSYF0g153EEtFmeTk72
-----END PRIVATE KEY-----
`
	fakeCert2 = `-----BEGIN CERTIFICATE-----
MIIB+jCCAaCgAwIBAgIJAOtRkOrJBEY0MAoGCCqGSM49BAMCMHgxCzAJBgNVBAYT
AlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcMA04vQTEgMB4GA1UECgwXU2VsZi1z
aWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMMIjEyMC4wLjAuMTogU2VsZi1zaWdu
ZWQgY2VydGlmaWNhdGUwHhcNMjAxMjAxMDQzMTU1WhcNMjIxMjAxMDQzMTU1WjB4
MQswCQYDVQQGEwJYWDEMMAoGA1UECAwDTi9BMQwwCgYDVQQHDANOL0ExIDAeBgNV
BAoMF1NlbGYtc2lnbmVkIGNlcnRpZmljYXRlMSswKQYDVQQDDCIxMjAuMC4wLjE6
IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEV+TyemWvmZGL5YjrSjtnwmyRtO/z8J6wQx2cz263VtEyTWfabEI49HYBtefy
Ypp9WJ50mBdINedxBLRZnk5O9qMTMBEwDwYDVR0RBAgwBocEfwAAATAKBggqhkjO
PQQDAgNIADBFAiEA+g3X1x27qV+LRx81AudIagHdvcVvLVbRJh0eXNFfPzUCIFHg
JSnRKkDuZ/d5wYR59eIld9FsJPFWPCQth2cKnBsM
-----END CERTIFICATE-----
`
)

func TestSingleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, false, t)
}

func TestSingleRecordTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, false, t)
}

func TestMultipleRecordUDPTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, t)
}

func TestMultipleRecordTCPTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, true, false, t)
}

func TestTLSTransport(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, true, t)
}

func TestDTLSTransport(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, true, t)
}

func testExporterToCollector(address net.Addr, isMultipleRecord bool, isEncrypted bool, t *testing.T) {
	// Initialize collecting process
	messages := make([]*entities.Message, 0)
	cpInput := collector.CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   isEncrypted,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	if isEncrypted {
		if address.Network() == "tcp" {
			cpInput.ServerCert = []byte(fakeCert)
			cpInput.ServerKey = []byte(fakeKey)
		} else if address.Network() == "udp" {
			cpInput.ServerCert = []byte(fakeCert2)
			cpInput.ServerKey = []byte(fakeKey2)
		}
	}
	cp, _ := collector.InitCollectingProcess(cpInput)
	// Start collecting process
	go cp.Start()
	go func() { // Start exporting process in go routine
		waitForCollectorReady(t, cp)
		epInput := exporter.ExporterInput{
			CollectorAddr:       cp.GetAddress(),
			ObservationDomainID: 1,
			TempRefTimeout:      0,
			PathMTU:             0,
			IsEncrypted:         isEncrypted,
			Cert:                nil,
		}
		if isEncrypted {
			if address.Network() == "tcp" { // use TLS
				epInput.Cert = []byte(fakeCert)
			} else if address.Network() == "udp" { // use DTLS
				epInput.Cert = []byte(fakeCert2)
			}
		}
		export, err := exporter.InitExportingProcess(epInput)
		if err != nil {
			klog.Fatalf("Got error when connecting to %s", cp.GetAddress().String())
		}

		// Create template record with 5 fields
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

		element, err = registry.GetInfoElement("reverseOctetDeltaCount", registry.IANAReversedEnterpriseID)
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

		element, err = registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name flowStartSeconds")
		}
		ie = entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
		templateSet.AddRecord(elements, templateID)

		// Send template record
		_, err = export.SendSet(templateSet)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
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

		element, err = registry.GetInfoElement("reverseOctetDeltaCount", registry.IANAReversedEnterpriseID)
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

		element, err = registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
		if err != nil {
			klog.Errorf("Did not find the element with name flowStartSeconds")
		}
		ie = entities.NewInfoElementWithValue(element, uint32(1257894000))
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

			element, err = registry.GetInfoElement("reverseOctetDeltaCount", registry.IANAReversedEnterpriseID)
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

			element, err = registry.GetInfoElement("flowStartSeconds", registry.IANAEnterpriseID)
			if err != nil {
				klog.Errorf("Did not find the element with name flowStartSeconds")
			}
			ie = entities.NewInfoElementWithValue(element, uint32(1257894000))
			elements = append(elements, ie)

			dataSet.AddRecord(elements, templateID)
		}

		// Send data set
		_, err = export.SendSet(dataSet)
		if err != nil {
			klog.Fatalf("Got error when sending record: %v", err)
		}
		export.CloseConnToCollector() // Close exporting process
	}()

	for message := range cp.GetMsgChan() {
		messages = append(messages, message)
		if len(messages) == 2 {
			cp.CloseMsgChan()
		}
	}
	cp.Stop() // Close collecting process
	templateMsg := messages[0]

	assert.Equal(t, uint16(10), templateMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), templateMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	templateSet := templateMsg.GetSet()
	templateElements := templateSet.GetRecords()[0].GetOrderedElementList()
	assert.Equal(t, uint32(0), templateElements[0].Element.EnterpriseId, "Template record is not stored correctly.")
	assert.Equal(t, "sourceIPv4Address", templateElements[0].Element.Name, "Template record is not stored correctly.")
	assert.Equal(t, "destinationIPv4Address", templateElements[1].Element.Name, "Template record is not stored correctly.")
	assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[2].Element.EnterpriseId, "Template record is not stored correctly.")
	assert.Equal(t, registry.AntreaEnterpriseID, templateElements[3].Element.EnterpriseId, "Template record is not stored correctly.")

	dataMsg := messages[1]
	assert.Equal(t, uint16(10), dataMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), dataMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	dataSet := dataMsg.GetSet()
	dataElements := dataSet.GetRecords()[0].GetOrderedElementList()
	assert.Equal(t, net.IP([]byte{1, 2, 3, 4}), dataElements[0].Value, "DataSet does not store elements (IANA) correctly.")
	assert.Equal(t, uint64(12345678), dataElements[2].Value, "DataSet does not store reverse information elements (IANA) correctly.")
	assert.Equal(t, "pod1", dataElements[3].Value, "DataSet does not store elements (Antrea) correctly.")
	assert.Equal(t, uint32(1257894000), dataElements[4].Value, "DataSet does not store elements (IANA) correctly.")
	if isMultipleRecord {
		dataElements := dataSet.GetRecords()[1].GetOrderedElementList()
		assert.Equal(t, net.IP([]byte{4, 3, 2, 1}), dataElements[0].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, uint64(0), dataElements[2].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, "pod2", dataElements[3].Value, "DataSet does not store multiple records correctly.")
		assert.Equal(t, uint32(1257894000), dataElements[4].Value, "DataSet does not store elements (IANA) correctly.")
	}
}
