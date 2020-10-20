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
	fakeKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCvTekfTcktH3bp
sB+pRW9B9OqtjmXumWKLsKJq0MxA0gUuRfKr3dc5uKexk2HDM/gTCEMhDSe+SrAF
PNE6oIb69us8V53XB1AxCQM1G2gZB277Glaw/3o0fxSOXxGYnYO7ac44rrjudqMl
Tp7DPoQaa0rp00G6eBuzOewUmSxj/i5p5t+i8s5kj5ny014NcXAoVGeec0lI35qp
+/gda3u+E70BgKxCxaF9bE0DQmE0GClzSKULclV+UBCuoCCgU2iyajVMsUNapelt
vJC+qjHEpsTGGzSsb0LTCktjSQRooYYkMccmafLpTDhEa0Qmt2L8ilwlxg6c1PRv
XE25qncPAgMBAAECggEBAJE/z6GFVOPTRza3HHSnOFkA8hVdgC2i31j4wIoaeLJY
kbxWboxiofqMej2S7RTNEYXLebt/5+cugQvF6WJXMZ/tSNlVi01oHNSUMBknnSfn
1deuahf7hijLBqA0OyMll8mIEDs84bOLjv/RVZBWUySEs6xrwvEapXDp1Cb5ByPN
T1iGZ3chcOgGPX6MTq9+P4yREREQXjPZ9uKSiLqQg2rVg/j4sC/iPgiE/nSShPIk
gpOW3kgUuiYGsTQSJ2YIyr81MEgudmUCnJbu/5P8dqtHiqmHOW1psirwVB7xCow3
h8JBuxz2jHTqnsAfXwWdmvZyXvAycR+9/t9CCGwee3kCgYEA1ozhdC5h6MfyaagP
9Hl0i8Jlh6r1WVMXLpPy0pQGPnw1JJUHHiEIU4Yp/tzO+DHOSe2mvKLGrsNIRH89
Vh0maStI26brPyiw7w5hjelxrJ/zH0UdWzWxbZ8HRNh8F3WGoXkGoaLRMQUfYvOI
lT/HlOSmyl9UCByzU7sq5bkIU50CgYEA0SwFyGX/rpBC7YWpe1VsLBF8GSat9SUc
UAXn0/6x4eOvLtdPk67HrnU3FIvV376HuTY5hCC2sQTJ+cxzhAj3cpbJjOpjlJZj
nAYrVNAQHmgynKjCNP8v2W8LQbi39UPE5Zf6dphFbpgQgqYqMQV0iIWRv4WKJKAD
w3GMwB6pA5sCgYEAlHT/PAksLorMLlfgUmYIQvzMjEe7ZYedLtmo2BUdDPedPibw
ueRZgpH/VR8tB4hPGdCb40Mu/5aY1uzEYGXjQjp1O6gQd6+MXp4w2qWBxtUWwbht
S8OndhboTLcPhpwIAItiD04+OhE1Wp7xD3UGgPyGfNnhp4tUese0MykJnfECgYEA
ok8MtbIgMq6SoIjFOITSiWeP6lxPRBhl3dqXR7MtCOGKQEim4SwQmlkuQm03qoTI
AHoJK3PPD5FtwL5bLKtgh7Rl9UizuMrxxFItMYS53T5xd4qkGEekM46tJ3RUmqbZ
lGbX3UrPJcAtn5Oczak0AfPTYtAWn9Di2rezxiiEcd0CgYA0RSCk8XgtZxAoPQJC
Y2PJ6FHlSLMtDhsAsUtD+mXlt8+o+tyMG7ZysQZKHsjDMzEZZRK7F8W9+xzzl1fa
Ok+B9v1BFakMXRc5zcA8XH1ng9Ml2DfVYPXxwmaMsGPnwPZsftUJPNbArS60vJJh
w9ajWgCA6SGtD17ZpHfgIiMvhA==
-----END PRIVATE KEY-----
`
	fakeCert = `-----BEGIN CERTIFICATE-----
MIIDhjCCAm6gAwIBAgIJAP3U+C7liWf8MA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNV
BAYTAlhYMQwwCgYDVQQIDANOL0ExDDAKBgNVBAcMA04vQTEgMB4GA1UECgwXU2Vs
Zi1zaWduZWQgY2VydGlmaWNhdGUxKzApBgNVBAMMIjEyMC4wLjAuMTogU2VsZi1z
aWduZWQgY2VydGlmaWNhdGUwHhcNMjAxMTA1MDU0NjUyWhcNMjIxMTA1MDU0NjUy
WjB4MQswCQYDVQQGEwJYWDEMMAoGA1UECAwDTi9BMQwwCgYDVQQHDANOL0ExIDAe
BgNVBAoMF1NlbGYtc2lnbmVkIGNlcnRpZmljYXRlMSswKQYDVQQDDCIxMjAuMC4w
LjE6IFNlbGYtc2lnbmVkIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAr03pH03JLR926bAfqUVvQfTqrY5l7plii7CiatDMQNIFLkXy
q93XObinsZNhwzP4EwhDIQ0nvkqwBTzROqCG+vbrPFed1wdQMQkDNRtoGQdu+xpW
sP96NH8Ujl8RmJ2Du2nOOK647najJU6ewz6EGmtK6dNBungbsznsFJksY/4uaebf
ovLOZI+Z8tNeDXFwKFRnnnNJSN+aqfv4HWt7vhO9AYCsQsWhfWxNA0JhNBgpc0il
C3JVflAQrqAgoFNosmo1TLFDWqXpbbyQvqoxxKbExhs0rG9C0wpLY0kEaKGGJDHH
Jmny6Uw4RGtEJrdi/IpcJcYOnNT0b1xNuap3DwIDAQABoxMwETAPBgNVHREECDAG
hwQAAAAAMA0GCSqGSIb3DQEBCwUAA4IBAQAE6/mSUMVerL8B3Xs2+3YVmhd94Ql5
ZKLwmEhsvOhP/3KRSncA8bIr4ZGCyvyEgsJqktjHJ4OYUIw3auYOBZgnUe3kM4NI
H7SS1JEtMu7okoXL/zHZcNrGHslFoEnIzvtoooSTQglcHclo8NWnGng6nJkSsY7w
DivAX9M7xtyKvGFgh6HuKYSZ3Yd6DeCkpnL2aOXf7cmFk4FT3SIbrtLNsLetbPl3
rsA9pUDwTYRP8PDOLC3BKyDl84Dpb8JScqVpBMDRBW1dre0emORlh17JllyhA+9b
fKNX/D1XinAd/OftM5gYBWs7M6uZTm7JxMCvA2kckoN7B+BdrzisxTUR
-----END CERTIFICATE-----
`
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
		IsEncrypted:         false,
		Cert:                nil,
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
		IsEncrypted:         false,
		Cert:                nil,
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
		IsEncrypted:         false,
		Cert:                nil,
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
		IsEncrypted:         false,
		Cert:                nil,
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
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4830")
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
		Cert:                []byte(fakeCert),
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
		Cert:                []byte(fakeCert2),
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
