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
	fakeClientKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAoUQTPOogam7LFPQPLbWf5tI/2KQT/G/8ptPWICJBv6Olc38s
WEs+31Vb+ecIqZoKGJcRnTYYfM+DNpzHSNGxCgQw7PVLb40F21XUVLGWn+jRsdOX
pSRFmzGXdFFDt6lQcmo+AAxnHYTpbOtC2bLwPHAWb88D5HTN/eyDZgWcWGzSSSAU
/kv/mRVC4Mvo6N4JTVEfg6q/ON2mMlq8JQOu2/vy116wg9A+fsxJNii6Y3oylB9r
/ocARj0i/Dl5vkCn3tL26z8erbJZ4zKK8Tlr5n9SS2TcKGdE4frhWc9RSu8hrlMx
KMsc/nrT2Z8UiW016vSeoVknot48YDrfiIG1fwIDAQABAoIBAC7AJG+ZVBJm0hrd
8fSHXba1puqwDlc1Q+I9MSsZo0PiNhm4eWuTTMPD5CkbUAiS7nBYgzO3Nfwg0GIp
qyAyIgfMVT6skdTh5hvC0w5GeWscPIY32BN443DtPIHs+RuqSvcQU68B6XbGTEFW
Jogj9r8eo3KAahl1vy3oveL6p2t+krK/ZKSwmy32XbPWk/yDjhBg1qc+s8JcgwOt
TluwAXdouj5CGRdYW6Ke1tZjEX7XeYIM/hZWi43zN07wTpu+Tr5FisPv3bL95gkd
oCYuZMVuCv2C/po+5B20Xg4APqx6bMitnn1Q4Fr7kooD06oNMDelVWXSpMQOCfjr
gQMWssECgYEA1j1c7FVaO9+9EK4Zc2XtLIGp9XrYe62l42RLzoG3fiEKnY98lb+U
j7SPmCj+jzgfwZW6Mk49k1Lu//tdDQPwPeQFCLJsHM+Lg8RP+PGyOI6Ju5li4gnt
GGjEQ2E+EYQjC1a0n8nJ/gMAZjQqTcP2qugTBfLLlYu0fgYre6ufmd8CgYEAwLNN
PTiCvMAFPR9+CFPF8FIg9XTM4zN4Cs89X8CquYDTNYWXYmPz2d4vrsH6l5XlTcO8
EOI6VfFlG2pKNOqKRDd2WLQiJbYqRaJwqu2q0GPYo9bAqkQ9Q7xZiFAKAtJ290u+
N4nH2IbRYo/8jHuVvv9pMEsqUuZOuvvXOs/UmGECgYBcoUt8I6tQF/z3KU93xao2
hBmoOeVAFGSVXNgqAYwEzOR6G4ASfzMMr1UmxRLLecjBOqu29H1LJaCQrW4eIoXN
PLmwePSlwFbiMg8h497a9UY4BqnqccBBvYqeV30utaMxU9vk+qqLWWDiz8s6tHAC
lTUkbUX48t6nXqOOZTYsoQKBgQC2vFGOsLwpyd4t7GNT+j1GfFuM6Moy2mgHuCb3
WnmLmEKyCpFYWHiyLiUBkCnW/eqJKAh76kxvm47JxK3CKHgd4Ip167xGDs1fY398
WA0XuNeD5u6liDigt0ggH+aebn8qW8VyXVIKXy7ITMqtXbTPft19Uoo8OvKGFrQv
rU5pgQKBgCvbr4nld950MfCo847xuz+6FfG0GkU73AIvV+q91j/EaZDc8wca53Cm
8h0tYVt6V0RjRMgm1dPif31Bqjh+6MNL+r1OzeKqvR+4fs5hjIli1zjRdUPyji3M
r2WO1njDA8V7+cKDMNef1QjDcvQhiG1wTHeZv5r04oX9hYIZymCi
-----END RSA PRIVATE KEY-----`
	fakeClientCert = `-----BEGIN CERTIFICATE-----
MIIC5jCCAc6gAwIBAgIJAPGVbUxq+B6lMA0GCSqGSIb3DQEBCwUAMB4xCzAJBgNV
BAYTAlVTMQ8wDQYDVQQKDAZ2bXdhcmUwHhcNMjAxMjA3MDQ1NzQwWhcNMjEwMTA2
MDQ1NzQwWjAyMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGdm13YXJlMRIwEAYDVQQD
DAkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChRBM8
6iBqbssU9A8ttZ/m0j/YpBP8b/ym09YgIkG/o6VzfyxYSz7fVVv55wipmgoYlxGd
Nhh8z4M2nMdI0bEKBDDs9UtvjQXbVdRUsZaf6NGx05elJEWbMZd0UUO3qVByaj4A
DGcdhOls60LZsvA8cBZvzwPkdM397INmBZxYbNJJIBT+S/+ZFULgy+jo3glNUR+D
qr843aYyWrwlA67b+/LXXrCD0D5+zEk2KLpjejKUH2v+hwBGPSL8OXm+QKfe0vbr
Px6tslnjMorxOWvmf1JLZNwoZ0Th+uFZz1FK7yGuUzEoyxz+etPZnxSJbTXq9J6h
WSei3jxgOt+IgbV/AgMBAAGjEzARMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcN
AQELBQADggEBAIIQYnFanVsvYx/PlzBzPpRlO5HIwx++7QpgBslhzTPcPZZkPLXv
H7iyrJcIOPkgn/7NgkUqMqbMJhWHZj74CIG1BOQ8kAI5qMhFftIWbKM8TiPwrUK4
WkMucQcHHDR4C2eHjBAhN9yb6YIyqY9WgJWUeuTLyLCpd1qRWe6X7sCULC7hrZNy
w64U3GILTYfG26shbTc9Pm+Isucygq6oZLLuWIJb4au0F7sVUUFkvMHv6iLRDXh8
AVqPbXBuAH8o02o4xGOYILfAz3hzW6W0UU90QMzB6/kWMy01rTb3/XmpHYmzldNY
fipw9vOnf6kfSufgQJ/AR7Vu1ueBXNohbcs=
-----END CERTIFICATE-----`
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

var (
	fields = []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"flowEndSeconds",
		"packetTotalCount",
		"packetDeltaCount",
	}
	antreaFields = []string{
		"sourcePodName",
		"destinationPodName",
		"destinationClusterIPv4",
		"destinationServicePort",
	}
	reverseFields = []string{
		"reversePacketTotalCount",
		"reversePacketDeltaCount",
	}
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
			cpInput.CACert = []byte(fakeCACert)
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
			CACert:              nil,
		}
		if isEncrypted {
			if address.Network() == "tcp" { // use TLS
				epInput.CACert = []byte(fakeCACert)
				epInput.ClientCert = []byte(fakeClientCert)
				epInput.ClientKey = []byte(fakeClientKey)
			} else if address.Network() == "udp" { // use DTLS
				epInput.CACert = []byte(fakeCert2)
			}
		}
		export, err := exporter.InitExportingProcess(epInput)
		if err != nil {
			t.Fatalf("Got error when connecting to %s", cp.GetAddress().String())
		}

		templateID := export.NewTemplateID()
		templateSet := createTemplateSet(templateID)
		// Send template record
		_, err = export.SendSet(templateSet)
		if err != nil {
			t.Fatalf("Got error when sending record: %v", err)
		}

		dataSet := createDataSet(templateID, isMultipleRecord)
		// Send data set
		_, err = export.SendSet(dataSet)
		if err != nil {
			t.Fatalf("Got error when sending record: %v", err)
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
	assert.Equal(t, len(templateElements), len(fields)+len(antreaFields)+len(reverseFields))
	assert.Equal(t, uint32(0), templateElements[0].Element.EnterpriseId, "Template record is not stored correctly.")
	assert.Equal(t, "sourceIPv4Address", templateElements[0].Element.Name, "Template record is not stored correctly.")
	assert.Equal(t, "destinationIPv4Address", templateElements[1].Element.Name, "Template record is not stored correctly.")
	assert.Equal(t, registry.IANAReversedEnterpriseID, templateElements[len(fields)+len(antreaFields)+1].Element.EnterpriseId, "Template record is not stored correctly.")
	assert.Equal(t, registry.AntreaEnterpriseID, templateElements[len(fields)+1].Element.EnterpriseId, "Template record is not stored correctly.")

	dataMsg := messages[1]
	assert.Equal(t, uint16(10), dataMsg.GetVersion(), "Version of flow record (template) should be 10.")
	assert.Equal(t, uint32(1), dataMsg.GetObsDomainID(), "ObsDomainID (template) should be 1.")
	dataSet := dataMsg.GetSet()
	record := dataSet.GetRecords()[0]
	for _, name := range fields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "sourceIPv4Address", "destinationIPv4Address":
			assert.Equal(t, net.IP([]byte{10, 0, 0, 1}), element.Value)
		case "sourceTransportPort", "destinationTransportPort":
			assert.Equal(t, uint16(1234), element.Value)
		case "protocolIdentifier":
			assert.Equal(t, uint8(6), element.Value)
		case "packetTotalCount", "packetDeltaCount":
			assert.Equal(t, uint64(500), element.Value)
		case "flowEndSeconds":
			assert.Equal(t, uint32(1257894000), element.Value)
		}
	}

	for _, name := range antreaFields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "destinationClusterIPv4":
			assert.Equal(t, net.IP([]byte{10, 0, 0, 2}), element.Value)
		case "sourcePodName", "destinationPodName":
			assert.Equal(t, "test_pod", element.Value)
		case "destinationServicePort":
			assert.Equal(t, uint16(4739), element.Value)
		}
	}

	for _, name := range reverseFields {
		element, exist := record.GetInfoElementWithValue(name)
		assert.True(t, exist)
		switch name {
		case "reversePacketTotalCount", "reversePacketDeltaCount":
			assert.Equal(t, uint64(10000), element.Value)
		}
	}

	if isMultipleRecord {
		record := dataSet.GetRecords()[1]
		for _, name := range fields {
			element, exist := record.GetInfoElementWithValue(name)
			assert.True(t, exist)
			switch name {
			case "sourceIPv4Address", "destinationIPv4Address":
				assert.Equal(t, net.IP([]byte{10, 0, 0, 3}), element.Value)
			case "sourceTransportPort", "destinationTransportPort":
				assert.Equal(t, uint16(5678), element.Value)
			case "protocolIdentifier":
				assert.Equal(t, uint8(17), element.Value)
			case "packetTotalCount", "packetDeltaCount":
				assert.Equal(t, uint64(200), element.Value)
			case "flowEndSeconds":
				assert.Equal(t, uint32(1257895000), element.Value)
			}
		}

		for _, name := range antreaFields {
			element, exist := record.GetInfoElementWithValue(name)
			assert.True(t, exist)
			switch name {
			case "destinationClusterIPv4":
				assert.Equal(t, net.IP([]byte{10, 0, 0, 4}), element.Value)
			case "sourcePodName", "destinationPodName":
				assert.Equal(t, "test_pod2", element.Value)
			case "destinationServicePort":
				assert.Equal(t, uint16(4739), element.Value)
			}
		}

		for _, name := range reverseFields {
			element, exist := record.GetInfoElementWithValue(name)
			assert.True(t, exist)
			switch name {
			case "reversePacketTotalCount", "reversePacketDeltaCount":
				assert.Equal(t, uint64(400), element.Value)
			}
		}
	}
}

func createTemplateSet(templateID uint16) entities.Set {
	templateSet := entities.NewSet(entities.Template, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
	for _, name := range fields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, name := range antreaFields {
		element, _ := registry.GetInfoElement(name, registry.AntreaEnterpriseID)
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	for _, name := range reverseFields {
		element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		ie := entities.NewInfoElementWithValue(element, nil)
		elements = append(elements, ie)
	}
	templateSet.AddRecord(elements, templateID)
	return templateSet
}

func createDataSet(templateID uint16, isMultipleRecord bool) entities.Set {
	dataSet := entities.NewSet(entities.Data, templateID, false)
	elements := make([]*entities.InfoElementWithValue, 0)
	for _, name := range fields {
		element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
		var ie *entities.InfoElementWithValue
		switch name {
		case "sourceIPv4Address", "destinationIPv4Address":
			ie = entities.NewInfoElementWithValue(element, net.ParseIP("10.0.0.1"))
		case "sourceTransportPort", "destinationTransportPort":
			ie = entities.NewInfoElementWithValue(element, uint16(1234))
		case "protocolIdentifier":
			ie = entities.NewInfoElementWithValue(element, uint8(6))
		case "packetTotalCount", "packetDeltaCount":
			ie = entities.NewInfoElementWithValue(element, uint64(500))
		case "flowEndSeconds":
			ie = entities.NewInfoElementWithValue(element, uint32(1257894000))
		}
		elements = append(elements, ie)
	}

	for _, name := range antreaFields {
		element, _ := registry.GetInfoElement(name, registry.AntreaEnterpriseID)
		var ie *entities.InfoElementWithValue
		switch name {
		case "destinationClusterIPv4":
			ie = entities.NewInfoElementWithValue(element, net.ParseIP("10.0.0.2"))
		case "sourcePodName", "destinationPodName":
			ie = entities.NewInfoElementWithValue(element, "test_pod")
		case "destinationServicePort":
			ie = entities.NewInfoElementWithValue(element, uint16(4739))
		}
		elements = append(elements, ie)
	}

	for _, name := range reverseFields {
		element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
		var ie *entities.InfoElementWithValue
		switch name {
		case "reversePacketTotalCount", "reversePacketDeltaCount":
			ie = entities.NewInfoElementWithValue(element, uint64(10000))
		}
		elements = append(elements, ie)
	}

	dataSet.AddRecord(elements, templateID)

	if isMultipleRecord {
		elements = make([]*entities.InfoElementWithValue, 0)
		for _, name := range fields {
			element, _ := registry.GetInfoElement(name, registry.IANAEnterpriseID)
			var ie *entities.InfoElementWithValue
			switch name {
			case "sourceIPv4Address", "destinationIPv4Address":
				ie = entities.NewInfoElementWithValue(element, net.ParseIP("10.0.0.3"))
			case "sourceTransportPort", "destinationTransportPort":
				ie = entities.NewInfoElementWithValue(element, uint16(5678))
			case "protocolIdentifier":
				ie = entities.NewInfoElementWithValue(element, uint8(17))
			case "packetTotalCount", "packetDeltaCount":
				ie = entities.NewInfoElementWithValue(element, uint64(200))
			case "flowEndSeconds":
				ie = entities.NewInfoElementWithValue(element, uint32(1257895000))
			}
			elements = append(elements, ie)
		}

		for _, name := range antreaFields {
			element, _ := registry.GetInfoElement(name, registry.AntreaEnterpriseID)
			var ie *entities.InfoElementWithValue
			switch name {
			case "destinationClusterIPv4":
				ie = entities.NewInfoElementWithValue(element, net.ParseIP("10.0.0.4"))
			case "sourcePodName", "destinationPodName":
				ie = entities.NewInfoElementWithValue(element, "test_pod2")
			case "destinationServicePort":
				ie = entities.NewInfoElementWithValue(element, uint16(4739))
			}
			elements = append(elements, ie)
		}

		for _, name := range reverseFields {
			element, _ := registry.GetInfoElement(name, registry.IANAReversedEnterpriseID)
			var ie *entities.InfoElementWithValue
			switch name {
			case "reversePacketTotalCount", "reversePacketDeltaCount":
				ie = entities.NewInfoElementWithValue(element, uint64(400))
			}
			elements = append(elements, ie)
		}

		dataSet.AddRecord(elements, templateID)
	}

	return dataSet
}
