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

func TestSingleRecordTCPTransportIPv6(t *testing.T) {
	address, err := net.ResolveTCPAddr("tcp", "[::1]:0")
	if err != nil {
		t.Error(err)
	}
	testExporterToCollector(address, false, false, t)
}

func TestSingleRecordUDPTransportIPv6(t *testing.T) {
	address, err := net.ResolveUDPAddr("udp", "[::1]:0")
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
		Address:       address.String(),
		Protocol:      address.Network(),
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
			CollectorAddress:    cp.GetAddress().String(),
			CollectorProtocol:   cp.GetAddress().Network(),
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
