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

package collector

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var validTemplatePacket = []byte{0, 10, 0, 40, 95, 154, 107, 127, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 101, 255, 255, 0, 0, 220, 186}
var validDataPacket = []byte{0, 10, 0, 33, 95, 154, 108, 18, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 112, 111, 100, 49}

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

var elementsWithValue = []*entities.InfoElementWithValue{
	{Element: &entities.InfoElement{Name: "sourceIPv4Address", ElementId: 8, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationIPv4Address", ElementId: 12, DataType: 18, EnterpriseId: 0, Len: 4}, Value: nil},
	{Element: &entities.InfoElement{Name: "destinationNodeName", ElementId: 105, DataType: 13, EnterpriseId: 55829, Len: 65535}, Value: nil},
}

func init() {
	registry.LoadRegistry()
}

func TestTCPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4730")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)

	go func() {
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "TCP Collecting Process should receive and store the received template.")
}

func TestUDPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4731")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)

	go func() {
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, _ := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "UDP Collecting Process should receive and store the received template.")

}

func TestTCPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4732")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}

	go cp.Start()

	// wait until collector is ready
	waitForCollectorReady(t, address)

	go func() {
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		conn.Write(validDataPacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
}

func TestUDPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4733")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	// Add the templates before sending data record
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}

	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)

	go func() {
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validDataPacket)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
}

func TestTCPCollectingProcess_ConcurrentClient(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4734")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, _ := InitCollectingProcess(input)
	go func() {
		// wait until collector is ready
		waitForCollectorReady(t, address)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
	}()
	go func() {
		// wait until collector is ready
		waitForCollectorReady(t, address)
		_, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Errorf("Cannot establish connection to %s", address.String())
		}
		time.Sleep(time.Millisecond)
		assert.Equal(t, 4, cp.getClientCount(), "There should be 4 tcp clients.")
		cp.Stop()
	}()
	cp.Start()
}

func TestUDPCollectingProcess_ConcurrentClient(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4735")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, _ := InitCollectingProcess(input)
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)
	go func() {
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
	}()
	go func() {
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		conn.Write(validTemplatePacket)
		time.Sleep(time.Millisecond)
		assert.Equal(t, 2, cp.getClientCount(), "There should be two tcp clients.")
	}()
	// there should be two messages received
	<-cp.GetMsgChan()
	<-cp.GetMsgChan()
	cp.Stop()
}

func TestCollectingProcess_DecodeTemplateRecord(t *testing.T) {
	cp := CollectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.mutex = sync.RWMutex{}
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4736")
	if err != nil {
		t.Error(err)
	}
	cp.address = address
	cp.messageChan = make(chan *entities.Message)
	go func() { // remove the message from the message channel
		for range cp.GetMsgChan() {
		}
	}()
	message, err := cp.decodePacket(bytes.NewBuffer(validTemplatePacket), address.String())
	if err != nil {
		t.Fatalf("Got error in decoding template record: %v", err)
	}
	assert.Equal(t, uint16(10), message.GetVersion(), "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.GetObsDomainID(), "Flow record obsDomainID should be 1.")
	assert.NotNil(t, cp.templatesMap[message.GetObsDomainID()], "Template should be stored in template map")

	templateSet := message.GetSet()
	assert.NotNil(t, templateSet, "Template record should be stored in message flowset")
	sourceIPv4Address, exist := templateSet.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, uint32(0), sourceIPv4Address.Element.EnterpriseId, "Template record is not stored correctly.")
	// Invalid version
	templateRecord := []byte{0, 9, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
	_, err = cp.decodePacket(bytes.NewBuffer(templateRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for invalid version")
	// Malformed record
	templateRecord = []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	_, err = cp.decodePacket(bytes.NewBuffer(templateRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed template record")
	if _, exist := cp.templatesMap[uint32(1)]; exist {
		t.Fatal("Template should not be stored for malformed template record")
	}
}

func TestCollectingProcess_DecodeDataRecord(t *testing.T) {
	cp := CollectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*entities.InfoElement)
	cp.mutex = sync.RWMutex{}
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4737")
	if err != nil {
		t.Error(err)
	}
	cp.address = address
	cp.messageChan = make(chan *entities.Message)
	go func() { // remove the message from the message channel
		for range cp.GetMsgChan() {
		}
	}()
	// Decode without template
	_, err = cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.NotNil(t, err, "Error should be logged if corresponding template does not exist.")
	// Decode with template
	cp.addTemplate(uint32(1), uint16(256), elementsWithValue)
	message, err := cp.decodePacket(bytes.NewBuffer(validDataPacket), address.String())
	assert.Nil(t, err, "Error should not be logged if corresponding template exists.")
	assert.Equal(t, uint16(10), message.GetVersion(), "Flow record version should be 10.")
	assert.Equal(t, uint32(1), message.GetObsDomainID(), "Flow record obsDomainID should be 1.")

	set := message.GetSet()
	assert.NotNil(t, set, "Data set should be stored in message set")
	ipAddress := net.IP([]byte{1, 2, 3, 4})
	sourceIPv4Address, exist := set.GetRecords()[0].GetInfoElementWithValue("sourceIPv4Address")
	assert.Equal(t, true, exist)
	assert.Equal(t, ipAddress, sourceIPv4Address.Value, "sourceIPv4Address should be decoded and stored correctly.")
	// Malformed data record
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.decodePacket(bytes.NewBuffer(dataRecord), address.String())
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4738")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   1,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)
	go func() {
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		if err != nil {
			t.Errorf("Error in sending data to collector: %v", err)
		}
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	template, err := cp.getTemplate(1, 256)
	assert.NotNil(t, template, "Template should be stored in the template map.")
	assert.Nil(t, err, "Template should be stored in the template map.")
	time.Sleep(2 * time.Second)
	template, err = cp.getTemplate(1, 256)
	assert.Nil(t, template, "Template should be deleted after 5 seconds.")
	assert.NotNil(t, err, "Template should be deleted after 5 seconds.")
}

func TestTLSCollectingProcess(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:4739")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   true,
		CACert:        []byte(fakeCACert),
		ServerCert:    []byte(fakeCert),
		ServerKey:     []byte(fakeKey),
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("Collecting Process does not initiate correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)
	go func() {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(fakeCACert))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		cert, err := tls.X509KeyPair([]byte(fakeClientCert), []byte(fakeClientKey))
		if err != nil {
			t.Error(err)
		}
		config := &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{cert},
		}

		conn, err := tls.Dial("tcp", address.String(), config)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		assert.NoError(t, err)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	assert.NotNil(t, cp.templatesMap[1], "TLS Collecting Process should receive and store the received template.")
}

func TestDTLSCollectingProcess(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "0.0.0.0:4740")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   true,
		ServerCert:    []byte(fakeCert2),
		ServerKey:     []byte(fakeKey2),
	}
	cp, err := InitCollectingProcess(input)
	if err != nil {
		t.Fatalf("DTLS Collecting Process does not initiate correctly: %v", err)
	}
	go cp.Start()
	// wait until collector is ready
	waitForCollectorReady(t, address)
	go func() {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(fakeCert2))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		config := &dtls.Config{RootCAs: roots,
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret}

		conn, err := dtls.Dial("udp", address, config)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, err = conn.Write(validTemplatePacket)
		assert.NoError(t, err)
	}()
	<-cp.GetMsgChan()
	cp.Stop()
	assert.NotNil(t, cp.templatesMap[1], "DTLS Collecting Process should receive and store the received template.")
}

func waitForCollectorReady(t *testing.T, address net.Addr) {
	checkConn := func() (bool, error) {
		if _, err := net.Dial(address.Network(), address.String()); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := wait.Poll(100*time.Millisecond, 500*time.Millisecond, checkConn); err != nil {
		t.Errorf("Cannot establish connection to %s", address.String())
	}
}
