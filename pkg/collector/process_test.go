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
	address, err := net.ResolveTCPAddr("tcp", "0.0.0.0:4739")
	if err != nil {
		t.Error(err)
	}
	input := CollectorInput{
		Address:       address,
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   true,
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
		ok := roots.AppendCertsFromPEM([]byte(fakeCert))
		if !ok {
			t.Error("Failed to parse root certificate")
		}
		config := &tls.Config{RootCAs: roots}

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
