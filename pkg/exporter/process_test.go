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
)

const (
	// TODO: update the certs before 2022-02-01
	fakeCACert = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUe4gJCUY6fAkjtBFUjZTWmG3X4h0wDQYJKoZIhvcNAQEL
BQAwHjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBnZtd2FyZTAeFw0yMTAyMDIwMTIw
MzlaFw0zMTAxMzEwMTIwMzlaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZ2bXdh
cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2ww7EiAT71r2J5Nj+
XcfsfG3JIx7NYXPoEwiyasc5O0ntmcsOhWX295PkM/nq9gxUKRCRafjczl+KaCYG
GgUXUoNJnJN2Oy+uNEOwwJN/jH2ElMltAGyot6BE8QJwKxPqkzW9eY1XSAdelU86
QaAUlit8mXUx/8eOiafxcEQtZdnXyZV5ceniC5+QHQBpmcmssohS4rEFVFacIdSB
BxSzSI0UbT9fRL0ZDP03ki1kYbVTrLUSuYzVdGCbU7PKSkotP6umzIrcALKAS2wY
WhE0lig0S2PFJEHrPJUHWtdRSDttY4n+Lrhsa7t+SNYWQyPWnG/FSfviw32vyHki
K3NnAgMBAAGjUzBRMB0GA1UdDgQWBBR/fNirU4kPi113EE7J0M7k+JCmwDAfBgNV
HSMEGDAWgBR/fNirU4kPi113EE7J0M7k+JCmwDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQCXAY9rwUiGxDhObL4x83CZO+aLkl0yxwd2Qp+FaH/o
wkkLf/RlYIHpwAlaFly/z/MsThuQs0Ke2MZ11M/kDpjERCLTcoUldniezP6sT0Ha
vMzhhBivc96seWxc74sNc0+kGtygyvtV72AeKLtsM3qwZB3k11xmdGEf/DNZRC9s
iSeMFT+VQn7FS61YP2SPD0MQG5pcc7tkFbEbriC+0GuEc+emgQXZfb6lTxcCLthD
1ZefCNIvrZfwddLuO9UAS6vEwV1ngvnaxAYTiIVDX4JLxQryDSEY7SfdrEuY3HKi
q2Cb+bFmy+CfJsqSYvf+lxalkEiZnR4abVzUKb7JRYII
-----END CERTIFICATE-----`
	fakeKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoHOXzKUXHoPvhC82ut0XRE1obaKw9i8gwejf+GxzJDNEMlpI
WhcpNvFaydpF/jPP27eYLP1M6ow7ZKeXJ/khe+wLvfWsYBXBBz2qL++KjcEFhjop
mI1vQnNEss8lHSZ8whMTTybBM/UGsX4+6RZwp5BUecMZm+maXq5FSmMBB9dEBXpI
DlvEyjwPugyprkuXgWPtdLqzDMKMKUehm4fNcHvUVFiSWNMoTB7AVmSzXBHaLkC8
j1XJ0rnxE+uawoPp8QxqpOK8p46TKMuXtvzOgIwJ77a+lGkNXycHiQAMZD1tkAkD
tiFcxHLxeZ6AuoD3iXiXNn1iAD8FwTr80IFUVwIDAQABAoIBAG6sbPeepFzLGqot
uu2X1RWq4y5EexXEmi7Gx75eZ+l/ZznoJmHl+erI/hufcIoQCP8AG3pk2eorAkjC
hLPw1xTYU50a2WSJfNTWxw47h3GRw5K7ibeNT0IhqjBAS9RYmNNxPu9oxvlkuNIz
R4eVj+000+ANIBv4PR+zy12s/qf9z2uDiAK+wPC3koxfJEPzwN0MbHNoqCrSS4WA
U5Ia5gAErpjk/TB1CIn/VXbWfajGtPLQFIaj1vaWCfYincoHihqzzr+0eZI3GmEq
MzhgSgarWpVC8sUtmwwYmDwd5LBI1sB4J2jD+MZdkLgQPv88LMrpvHefVoIGCBnj
htnTqhECgYEAzoz+bxKsc1YVbx0nfkvsXmHTiu8ymXQkASNafCaGTUokH7ehVmBg
qla2GA67B/yU0CuPpXYOcy2drvHNY+4cW6JPMmR+kxOiUMUGlNDr2alB5dTSvPc3
VQlrAACff+L2dZnee0KZL/lWFAnUQvr/yUFDJkauu3r5S1red+AQ1VkCgYEAxt1J
fQkf60/ByIJ5FIKw7PM/qn6pZUwy7lrbSNZs46DKr3eBhPWkit1Y2Vr1CWPenZ8m
xeLNpvfDX37TQJVjstVIiOzNguXY1OGLJMiKqk8s0mCj0hazCRNE0cqoQBYT3VrJ
2Qa1NG5WjHqvnO45YNjotygzjf9Tbp3oN8cRUS8CgYEAmh0DXtbdCzWIyp5DMG3v
0EBHudtdsrfAgYTiZ83K2XJfX7cAz1Ub6xzFw0+CZ6QjWOuXw4pBn9jCVZ0fdddd
G1YQp3XqJ004B/HqRjFYONCcVaMlFk+S3oUnbBoK6D3tTLPhF7EKYYw1mL/4u31S
StTCCJYmm8ZWqc4EPgdWKAkCgYAmvvzPiNSYQ3ztNUakEWapdCeGb5FPtE4EFN2+
zlB+9VgoYe9xWW8Kw1/JUaiGgNfh/B1Q1wTcsE93rr04SyMWt+mfDAxqoZ/ismMq
8ovZ7P09rCifCV8uuHtjKMopWmPacBL93wm1Qn5Idqr6t4uka/7DmOialRHLbqbN
H1MnbwKBgQCjRVBouJWDCKlkkoTHqMdcMnFERwW7ccklH2eM7ErxWnxS3EUrN8dT
xqsurz+i8+xaAi7TMiIG4D3PprDBoomQFOs8skvwrOEqbz7rWAiaf8FoMFd1f5pH
1LjjKO6VscEZKi3pNhUQLDszjjyM7ol3k4sN79z2FKZ/cFf0SnoN0Q==
-----END RSA PRIVATE KEY-----`
	fakeCert = `-----BEGIN CERTIFICATE-----
MIIC3TCCAcWgAwIBAgIUc9wOjUVSKpTIZmPlqzvSJf+l0kMwDQYJKoZIhvcNAQEL
BQAwHjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBnZtd2FyZTAeFw0yMTAyMDIwMTM0
MDBaFw0zMTAxMzEwMTM0MDBaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZ2bXdh
cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgc5fMpRceg++ELza6
3RdETWhtorD2LyDB6N/4bHMkM0QyWkhaFyk28VrJ2kX+M8/bt5gs/UzqjDtkp5cn
+SF77Au99axgFcEHPaov74qNwQWGOimYjW9Cc0SyzyUdJnzCExNPJsEz9Qaxfj7p
FnCnkFR5wxmb6ZperkVKYwEH10QFekgOW8TKPA+6DKmuS5eBY+10urMMwowpR6Gb
h81we9RUWJJY0yhMHsBWZLNcEdouQLyPVcnSufET65rCg+nxDGqk4rynjpMoy5e2
/M6AjAnvtr6UaQ1fJweJAAxkPW2QCQO2IVzEcvF5noC6gPeJeJc2fWIAPwXBOvzQ
gVRXAgMBAAGjEzARMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcNAQELBQADggEB
AKtIqKgLhYT21Ngm4eiKuWma0KLEJGJMFSijHO7LLwq3I90A6OA6sjmv9OsfNsRi
sBZSm8IT4+SIG3o4tAhgFfZjdmBNuY1ImDFoUfV6wfddi3cihNb5kLu2qv1SlUI4
P1EAXOLPAEvs7uJbrWNCi6sZD6AThDh7vQzqHuFkTRBxN7fI7uLznl5ue3JW9Z77
Cg8bBqbQ25otfo06J5QLXxXdHKipHZVlGyC+cbrqyKgOL/vYJZLr0maZQHwBzUOG
i5kKdHpUBCRoun1ZKzumSZZ3xXeDMdm49uCtFrr5ylfWuEOsentOfGaElaUSdAud
63BrM6BAmp/kxVLXZSo6JfI=
-----END CERTIFICATE-----`
	fakeKey2 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1h0K9jGfyBQMttaz
ija4rnsXfTQf1KvXl2o9SABhtvmhRANCAAQnICXGTyc72J2mpIgbZz3mvgmqUzGJ
FaU0IQHwImuqwIjbsJtnj6XgozycBwTPGPkuQeyKp3k3ADE7UOCqsSOH
-----END PRIVATE KEY-----
`
	fakeCert2 = `-----BEGIN CERTIFICATE-----
MIIB+jCCAaCgAwIBAgIJALfqenQRnGoHMAoGCCqGSM49BAMCMHgxCzAJBgNVBAYT
AlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcMA04vQTEgMB4GA1UECgwXU2VsZi1z
aWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMMIjEyMC4wLjAuMTogU2VsZi1zaWdu
ZWQgY2VydGlmaWNhdGUwHhcNMjAxMTA4MDgwNjQ2WhcNMjIxMTA4MDgwNjQ2WjB4
MQswCQYDVQQGEwJYWDEMMAoGA1UECAwDTi9BMQwwCgYDVQQHDANOL0ExIDAeBgNV
BAoMF1NlbGYtc2lnbmVkIGNlcnRpZmljYXRlMSswKQYDVQQDDCIxMjAuMC4wLjE6
IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAEJyAlxk8nO9idpqSIG2c95r4JqlMxiRWlNCEB8CJrqsCI27CbZ4+l4KM8nAcE
zxj5LkHsiqd5NwAxO1DgqrEjh6MTMBEwDwYDVR0RBAgwBocEfwAAATAKBggqhkjO
PQQDAgNIADBFAiEAzUT2hG3WChJh8cBo7EMQan2eJiF96OlSB+rWKKMaoGACIGOp
RVaPKj9ad0Z/3GiwaxtW+74bvc2vF3JS9cRU6DhY
-----END CERTIFICATE-----
`
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
		CollectorAddr:       listener.Addr(),
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
	templateSet := entities.NewSet(entities.Template, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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
	templateSet.AddRecord(elements, templateID)

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
		CollectorAddr:       conn.LocalAddr(),
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
	templateSet := entities.NewSet(entities.Template, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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

	templateSet.AddRecord(elements, templateID)

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
		CollectorAddr:       listener.Addr(),
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
	exporter.updateTemplate(templateID, []*entities.InfoElementWithValue{element1, element2}, 8)

	// Create data set with 1 data record
	dataSet := entities.NewSet(entities.Data, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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

	dataSet.AddRecord(elements, templateID)
	dataRecBuff := dataSet.GetRecords()[0].GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()

	bytesSent, err := exporter.SendSet(dataSet)
	assert.NoError(t, err)
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)

	// Create data set with multiple data records to test invalid message length
	// logic for TCP transport.
	dataSet = entities.NewSet(entities.Data, templateID, false)
	for i := 0; i < 10000; i++ {
		err := dataSet.AddRecord(elements, templateID)
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
		CollectorAddr:       conn.LocalAddr(),
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
	exporter.updateTemplate(templateID, []*entities.InfoElementWithValue{element1, element2}, 8)

	// Create data set with 1 data record
	dataSet := entities.NewSet(entities.Data, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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

	dataSet.AddRecord(elements, templateID)
	dataRecBuff := dataSet.GetRecords()[0].GetBuffer()
	dataRecBytes := dataRecBuff.Bytes()

	bytesSent, err := exporter.SendSet(dataSet)
	assert.NoError(t, err)
	// 28 is the size of the IPFIX message including all headers (20 bytes)
	assert.Equal(t, 28, bytesSent)
	assert.Equal(t, dataRecBytes, <-buffCh)
	assert.Equal(t, uint32(1), exporter.seqNumber)

	// Create data set with multiple data records to test invalid message length
	// logic for UDP transport.
	dataSet = entities.NewSet(entities.Data, templateID, false)
	for i := 0; i < 100; i++ {
		dataSet.AddRecord(elements, templateID)
	}
	_, err = exporter.SendSet(dataSet)
	assert.Error(t, err)

	exporter.CloseConnToCollector()
}

func TestExportingProcessWithTLS(t *testing.T) {
	// Create local server for testing
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:4739")
	if err != nil {
		t.Fatalf("Got error when resolving tcp address: %v", err)
	}
	cer, err := tls.X509KeyPair([]byte(fakeCert), []byte(fakeKey))
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
		CollectorAddr:       address,
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		IsEncrypted:         true,
		CACert:              []byte(fakeCACert),
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local tls server %s: %v", address, err)
	}
	t.Logf("Created exporter connecting to local tls server with address: %s", address)

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(entities.Template, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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
	templateSet.AddRecord(elements, templateID)

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
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4831")
	if err != nil {
		t.Fatalf("Got error when resolving udp address: %v", err)
	}
	cert, err := tls.X509KeyPair([]byte(fakeCert2), []byte(fakeKey2))
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
		t.Errorf("Cannot start dtls collecting process on 0.0.0.0:4739: %v", err)
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
		CollectorAddr:       address,
		ObservationDomainID: 1,
		TempRefTimeout:      0,
		IsEncrypted:         true,
		CACert:              []byte(fakeCert2),
	}
	exporter, err := InitExportingProcess(input)
	if err != nil {
		t.Fatalf("Got error when connecting to local dtls server %s: %v", address, err)
	}
	t.Logf("Created exporter connecting to local dtls server with address: %s", address)

	// Create template record with two fields
	templateID := exporter.NewTemplateID()
	templateSet := entities.NewSet(entities.Template, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
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
	templateSet.AddRecord(elements, templateID)

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
		CollectorAddr:       conn.LocalAddr(),
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
