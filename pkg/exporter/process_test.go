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
	fakeCACert = `-----BEGIN CERTIFICATE-----
MIICuDCCAaACCQCTFBmkg1kiDDANBgkqhkiG9w0BAQsFADAeMQswCQYDVQQGEwJV
UzEPMA0GA1UECgwGdm13YXJlMB4XDTIwMTIwNzAxMDkxM1oXDTMwMTIwNTAxMDkx
M1owHjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBnZtd2FyZTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAOIpBF9+FGklbj+ldmiIDeVs5CYWATx+UTd+pnNu
sXs2+nJ3ZZZJIrWcOU2DEFq0rXQ6/+AtRhqvTFbYAuFEzzTseTnJAYiqW7dyEMyK
PV4uMrQtWzWp/m6AM48fwmAEWyhDJc6RtGcq+v12uf8z24rA2CMNsW9Axz2Y/XHT
80eqOr+iiCRApjPVpZrbM2XBH8xgHcUYkMPJmRyUy9IN+CEn5U83YIrXMY2yo7HI
mTZk+YMwaBkhdGxYTgwLRSwplHhx4ETL6mrH3s7HjoOW40RrEDtwe1iHcJlLK9a9
8KzJ43AIZpXdzrrGRseW0CjTGhh31kNfS8P6FzwWKM70U7MCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAV3heF6HdlDEJIfJUQGVufvO+vLILEswZ3/Da6/qWRk2qdSVV
bcVez08JXp+9K78J7M86XNW20Uf8KVOrMCuVL7PjfVsConTfD6FBcVgXLOFqc/oq
YJ/113OikVys5nXf+4Vgc/drLYmEPTFwkjlqC3MYS99jmyfXUdrnhQICgKw5KkvX
IrXAj6dkjnj2QkUgIiRkpqdNiZN/8q5kH2vLmBm5/R5yFlcOlW2xGex/9XoA7GCJ
BUO+0EqD41M72He2fvAIXmPgcQHz9kHQYa4u1sI021qoe69lX0AD+T4E6ducLTlc
RzZwnry3SsMgqT7Yx6dtd+8Ghl9zblA43kvlyw==
-----END CERTIFICATE-----`
	fakeKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwaOGeO67mLjYmx3i6HZsI0HzMPf1wN3OtyCMZVpRhVFIPewf
wOwilVkVliZKxgVdPuGJxnWPg3qrSa+kY0B/TUeW35GR7UC4uH9inOVvtTfGc/C+
7ZrkYG957xTlharMQJUeoocf+oXBN3NI+/DMPh/ttwNGdSTTd4XBJIPbf8PHOSF1
malBNgF4z0ns/i45TFvWcqARH8SXqRDHTBrIKNY+kS/AaTvGoin7ER/sHnP0U8sz
zygP2BxY0gmEhuTbYssaZQgz36fRaLvLuyA8rjiG1AoHuCQC8AghnXOuQr/Rt0J4
RGOIUGYWZCQtwXzvkn8/x2t9uzrbBDNgsCx8ewIDAQABAoIBABBQB1cOvY0LHWxL
4z60Iz4BI0yfxvs9dFmnC0zKhA2YIF7fEnm9KtisDY59oVT3RLi0ZVfrtXBdGCr3
+gBGgbLv8fzZlZKIHkekq5kOFxAMJ9LCmEMKBm09VudWOlO9ZMGYDmGgwofnVrSm
KKLY0Uv2gp8lTn014f6yrOe3l/k2ToEBgX867JT1p1W9NOgPtWQLdYQdi5yE20dQ
1cP07r0ejvi3JkBGjKxZ4QY/bKa7MsRFV7KdVC2dDGGegzKyYtHd/cIJPqcitzBW
QKZw3ilvvkiIdY/qAjXtU43XsTku3amwMHUzT7+TWppFt3SlkNICQOF0VzZPqmRO
88aeF7ECgYEA4Zwz/1oT+C+2XUIG+TyXJiVwtzhQtS76CObye0oDZYpkFSLzhXij
LXXuR1z7MI60LsgvDqiJwEqqWMSL/ZaxlIEIFuZVOs0UFEjm5NtAhpf4/URL28La
exveYUAVRsK6cF9y46DcLQiixgl4ZQCmZN23Fzci/NpfiNSO32gE/hkCgYEA27jX
RkTxPhZHkemCcmwayVhOyb6A5K2U6zV6Sb7q4ruBUfGjQyx3ij8sGtI3PQPQ84Vk
Oe0HEQzyrDvo+J+5WbIakxi8HzdUhglGsMbbdrvJroz5AkFxrgoQjRLMBCNrTh7s
dhw8hTPdvFEyc19HJicfeaztusMj5sBvaMXdebMCgYEAyOSjtIyMXaJ2u8IQnZyj
ZtdN8AhYbY2gHY8wejIkpiU+C0gtGjua6d8qRyd3kPxxW3rr1BylVLHnz9VsZmnq
RLdE8cc2O37jk1B7MWw+n9rxXuySs+RlUdw1/9jlWTYKeAe2MRVLGVqoPrmuGBol
EIoQ/74cDJWTHi9P7YUddPkCgYEA2hpLJqd8yGKZPI+MO0Rv+nk8DCqcC2L6tdfp
wZZP1izGG68+nolfR82ZXC5bQqetHG3GpXFRWG1/3dPCWDlEZXLTyjv9UQc9UaeX
khZy9xNFCY1KCCEqVNYMw9xqw5jdBTjRBBTXRmnLqwj2iWuEVqzzI3ayrHbUBlPy
ww/V3t0CgYEA30RxlOoZEGKNv+vsTODhKYSrdyVdIi7pVRZ0/Lkq3mOIhKsTuxOu
Mmv3+8h7x+AvLTxPD2mmNWKLbi1kznswybOUkwDHj+McY+DKAxkvp1onMbs8n3Bs
k6q5/YacXNd2ELwlttgH4zr9akuauTguhKDig7+tse2Q/g5zUQHRhSw=
-----END RSA PRIVATE KEY-----`
	fakeCert = `-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIJAPGVbUxq+B6mMA0GCSqGSIb3DQEBCwUAMB4xCzAJBgNV
BAYTAlVTMQ8wDQYDVQQKDAZ2bXdhcmUwHhcNMjAxMjA3MDQ1NzU2WhcNMjEwMTA2
MDQ1NzU2WjAyMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGdm13YXJlMRIwEAYDVQQD
DAkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBo4Z4
7ruYuNibHeLodmwjQfMw9/XA3c63IIxlWlGFUUg97B/A7CKVWRWWJkrGBV0+4YnG
dY+DeqtJr6RjQH9NR5bfkZHtQLi4f2Kc5W+1N8Zz8L7tmuRgb3nvFOWFqsxAlR6i
hx/6hcE3c0j78Mw+H+23A0Z1JNN3hcEkg9t/w8c5IXWZqUE2AXjPSez+LjlMW9Zy
oBEfxJepEMdMGsgo1j6RL8BpO8aiKfsRH+wec/RTyzPPKA/YHFjSCYSG5Ntiyxpl
CDPfp9Fou8u7IDyuOIbUCge4JALwCCGdc65Cv9G3QnhEY4hQZhZkJC3BfO+Sfz/H
a327OtsEM2CwLHx7AgMBAAGjEzARMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcN
AQELBQADggEBALKkqdqBXGpKlquMhYvXSuyIe2GcbhOsHZhmTq2cCHzeObxZfzkI
GZjqWAsJ/sn/RXjjb+cvOtdY8LhgsQkNa60WV7LJjyylnBNQvrHK6i0+0oUUbyxf
Ps4MvMH+FjG1obfcPV5dCaJFeDOc/qP8MZQzbBnWDUiLnsyAvg/iCNOxjLqunPhr
I8nZH/JVsGPZn55Bg8ae6upxYX8Ho+BbgPHLwCImQA1vALaieu0yrm9MGB4KgUCf
rErlI+RVzS2DeDRNEeHLV3UL+BCjbP0B3Pg6FpDwpe15pnNz0JuBlEOuNmoPEJfE
iC9J/JWV3fWjsN4ysH4DajKshCMEx1dkNyw=
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
