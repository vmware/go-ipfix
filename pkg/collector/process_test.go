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
	fakeClientKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4JR4yX2LcOIdMI3lVml/OUwkjGkAVge0Vy4xCU8R+au1a+iS
EuIoTZwWXtqsdmwVUkn/534NtqPFNMfkgBcQPiiTwx4aYywQeMdMHjtW6vU1+nCK
u3C22+OcGedhAAreAzLVtO1rlPbK6px6evg3O3M9uo0QbE+rsTp5l59WC+rhHmXa
wJxQGmjDzYwaXYBVfOQrw0Fj4a12U5I3vwWbwLJ66D6GZRpJ8+uoaAkFHI2D2+y9
pFopoSjUbXFnXe5U3xvBHMkezHooBnjvcWxYQkhdUkWTmJBHLj+QrvyYxAg23U6Y
T8slbCUXWJglykOiFjyXyW45ifcZM+bjHIH/iQIDAQABAoIBAQCrI7mgIlHephEE
bT11SlOvQD0h2upspNZjEUpBA8Z48scAAm0+gqWf7vCFPDLs05Sz7rxalo6wvcCM
Zj/U9L5l/9oKeKg3Jt8uiwGQkDu+NTr7LEQsbsqKarsMamxa8e0ZluWQSNUQ4bjk
bHZRu1Grtjg2L0VypIv8NMlwJ/YUgW22Q7I8KUJfEc8W+/rkHdlbRsI1jEBYzN87
aLYdEx1WLoWV6BHL1l8ZxgDp66MPDSQk41tnM7SsiCtLtUO+wrmV11FAzyPkPcQB
y+xvNB5sifZxUnUJcGXeKmld3InqmHEaWh3D9mOg++tmyp9L1puQz7ip5ge8owuX
zJpJFgHZAoGBAO/X/iHt1spcvvsee1QV9ZrzDq+PFcprBq1ORo569yal/NBzAd14
n0zjdKoNww4RLFsAufDPkMbKWT8lyLCB7ATfIw9VZT1VE7X2YUx5NOGuV2sEpZal
B5wFRgpR+V0AlxENaRzSPX0qJh3bkONbFzcBefAK8oIvFNg73rFLev4LAoGBAO+1
QwxjIY0J3VcBvdZdOyqbOHWmuPvdsoDDj4qagR9sMUDsO4C/P4sSoe9qf80Zte0m
Ka9ISf8ooxx+JR0SFdnQLCnhDxLP2vJgtqxLBLKeruYWLZh7uQ+izofjs9VsWa7D
V4N57GMHrOAcfxVK9t2Og/e19dvwyxAVYdYyazk7AoGAHtf8Coj3klaTCOBGo+2f
BCo1vUX9W2agGTFzyWbu2b2G4Zeoqb6VXeHyYtwaNXjn51wUjW9kAuyKxaAqSuiq
XYYEkDg/KMAEJOZmZNtBfbRZ8Z1LXjAi5mGXPESGePtWcg7zcY1n8uy0sipGW7af
Kae68q+1uCAt4hDw9oPqcTkCgYEA7w+HXsM+orpD1JIYEcHJUCSdmjg8JHRloaVn
coPEYuIz/NucPDp/1OMwPOWpr5MErQ5yZC1kHuUYR0JHIUb4I9JJOTsLHWfOpAtw
I0Rt2vYG19Emh/xcBAwKjdu5bhAxIOoQTT87UUhGUPwagdHRggSv+EuwdzkeS1wH
xudhqCECgYEAwkXIdbnqCOyGWh3C35HDgfdeZNA1+fqEBgLlyLvgfW/qXdnCUxVm
VGX8km52RBiUscsGDDqprb+0KRZ6u7zusfSJ7JdcyFrYX98aGYuGfgouijB77B/N
p4JoYzCeQAMVBQDQivc1yY4PuRu5xcIn65a0KP//b5caPwY8FC5vHg4=
-----END RSA PRIVATE KEY-----`
	fakeClientCert = `-----BEGIN CERTIFICATE-----
MIIC3TCCAcWgAwIBAgIUc9wOjUVSKpTIZmPlqzvSJf+l0kIwDQYJKoZIhvcNAQEL
BQAwHjELMAkGA1UEBhMCVVMxDzANBgNVBAoMBnZtd2FyZTAeFw0yMTAyMDIwMTMy
MzRaFw0zMTAxMzEwMTMyMzRaMB4xCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZ2bXdh
cmUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDglHjJfYtw4h0wjeVW
aX85TCSMaQBWB7RXLjEJTxH5q7Vr6JIS4ihNnBZe2qx2bBVSSf/nfg22o8U0x+SA
FxA+KJPDHhpjLBB4x0weO1bq9TX6cIq7cLbb45wZ52EACt4DMtW07WuU9srqnHp6
+Dc7cz26jRBsT6uxOnmXn1YL6uEeZdrAnFAaaMPNjBpdgFV85CvDQWPhrXZTkje/
BZvAsnroPoZlGknz66hoCQUcjYPb7L2kWimhKNRtcWdd7lTfG8EcyR7MeigGeO9x
bFhCSF1SRZOYkEcuP5Cu/JjECDbdTphPyyVsJRdYmCXKQ6IWPJfJbjmJ9xkz5uMc
gf+JAgMBAAGjEzARMA8GA1UdEQQIMAaHBH8AAAEwDQYJKoZIhvcNAQELBQADggEB
AB9OivrucJqfuQ4UjUXcOLDyjmof7zQcFfp1OPQFpk6zGtV7ntbwENesBEA6E3Gu
doZvjo/EZva8niaYPI2Jd/vg9Ym5oDqhUwiXQdEjayiI17qxTccV17N/dgJ+qv/3
2spvqkT5A1t0F5nfy1hV6VkzYarOIXzbet9qTKVqmoaMxYA7mtz1kqYL77KMaRCk
CTJQCaLDSG9RrBzBGTU8aYIkCm9zRVpLCBICkzGqMS64qXjT7PZlUvOUkGX+B3ap
Dgp9/pRbYHDmj/F5kRavflNf3ilVBK4kkHEgH9YiDGZJ1E26Xkci9TQDbYA3zNdK
8nT1HsNN9cEArXP6ttJ6h4I=
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
		// function waitForCollectorReady may introduce more clients when testing connection
		assert.GreaterOrEqual(t, 2, cp.getClientCount(), "There should be at least two tcp clients.")
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
