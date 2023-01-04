// Copyright 2021 VMware, Inc.
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
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"time"
)

const (
	// TODO: update the certs before 2025-02-01
	FakeCACert = `-----BEGIN CERTIFICATE-----
MIIDuTCCAqGgAwIBAgIUUGJowvrmZZ+VDUYMcIvRsWgfl1gwDQYJKoZIhvcNAQEL
BQAwbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcM
CVBhbG8gQWx0bzEPMA0GA1UECgwGVk1XYXJlMQ8wDQYDVQQLDAZBbnRyZWExEjAQ
BgNVBAMMCTEyNy4wLjAuMTAeFw0yMjEyMDEwMTU1NTFaFw0yNTA4MjcwMTU1NTFa
MGwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlQ
YWxvIEFsdG8xDzANBgNVBAoMBlZNV2FyZTEPMA0GA1UECwwGQW50cmVhMRIwEAYD
VQQDDAkxMjcuMC4wLjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCn
XMWEw1v50MUkWmC8gXWRKwJwLq1taDwQPQ1DquT+xzdep1DUH31FxxxwDUn6Wn61
Dtxp+X+PP+S0TsOSxt3Fv1T5BvJVnh597m07pV5NOFrCoPnmuFHGrEk+4dQ16fUD
0SvtzWziGK9rrlBCcfVhYhvCCwjMjusPKi+CStSfboK1vCLC8tRBeRYDqIMdEa2Z
TuU4ZQnr3lz1wCHCERObqAg8MNaQhvQVvZPFRf9NQQ+QgcZL0Ds3Sm83gGBausgn
Wnh31HVkd/UIVp+jmuOk3ZYXH+Ps73QwXNtYAsOy706wAlNc8vWQy2nhTnylIXv5
/sAlhfzArNdHIUPxicAPAgMBAAGjUzBRMB0GA1UdDgQWBBTH5phxXaZZ9GZYq0Ds
zeiRqChSwDAfBgNVHSMEGDAWgBTH5phxXaZZ9GZYq0DszeiRqChSwDAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAWD2r2FS4KlJgoUZi8osn6P2VV
0MFAJOroP2oerAUcFuZoL/DQyj+2Sv1podg8KO1qnjYGlhtE+UUhXfRE3zM1FaLS
CvNRaN8q9SlvtEFeoRo8n+agNmmDKNNPGfekKP2ZDsl64ueJeY3vouCaRvHfBbrG
tnwDUXb7KEKfNz7o57Qw+QjgSQ6ALS2556nG3gNZvGnD/FACFe5xea7G0QSH13uN
jhRZ0eFkqyxAE4cGSZulvmBcWGggvrqNlRPQitHJKSFc6tYsOTnsF6X0Jjeh0mt/
y54hHPtePKrcFe1Hi4Zi3fqm1mtsExrYeH0JqG8p88CFXZbY0DSyINFBTj1C
-----END CERTIFICATE-----
`
	FakeKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDva4WDGv5anUe7
/3537BPXWodXUj/Mz671xFGSPxtmKikiIW0elfOyt35/SihNCBpfpIoRH0pvuSRM
BfA1TODzigH/I5vAFhu5VJ9RacPSEhTrHwWuBO1wXOq7HVw4UTbwRn8dgtIchKqr
co+Ba0KVAHoZm3tFwv6MQYBzVlzKlnUhi6fJTe2ObHnqV9dvAOgvEtqpQN4Bypw7
EWi0h7+l5XjMnJ+lKySYDsJ00f8VLsG91Sdr8Lds1P3snZ+ToHudUdSG/rjufRBc
s4r8LuFZOHmJjeymAVRbdlaUmepuLxdFKwYn6E1yewwkDXw1O/iSRCX4hSatB9kJ
Uohk3K5NAgMBAAECggEBAKIhEbyCnxQFxfoNPjs/ZwBCkbwUOpgbW8OaOhLrIUbB
7jDqqdY4fVrc35CbS0c+4X07EzQdGG8n1OiWbN/rO7owDsIT/vjI/+U05N5g3PZ4
wCmoTFRXieK5SUuEylpoxOdZFeOKH3aocFrBrWRamjAErqqAm63WKkIYaT+xkAyv
HzIX5Tz0hrrsef6S3qAGxnOyvwC4qdg/Ud7l127n7wnes6GSKVgfYmEaMa5sryyv
xER4rax/X3duyzghBdFoF1a0Ha4ffGPW7ynSvTMkyfcdTe3Bli9hmtvgvqzF+85r
zkeLC6sbPbdFV5ZFdhviKrsgmJrOQSAJMHHxr2DJFpECgYEA+47ySAAWpcu/q5pa
qZe3LJDo6UZU0yIDVvLHEh9Q4XLW0IMafAy1+PiRo9qijpsHLSiqPhZRuAqJ0toh
MVKZfiBy3Y/cXs/q8ChjxmBf9wNWdaV4S0RqcecV2t23Vygc3Km7b6ef9r22MQ80
wB43owKRPEZ5lrHTNewK9idBGpcCgYEA86W1jPtj+bTELIzIVXzPFUpDCABgklsx
DNrgscm1yKlYRq9SOMOIGWpNFm5DS9/wD2a9BfY6uHaKAUraZcuMoJnat4vtnVv/
CcuvgWKBYdVeMMY1CKEcoOT0XpBZPR120z3pWd/tp7+qQjjVzV06VYfhf+4ikSr6
Nl/Jvns2DrsCgYBKTtR0vknyWbhZmXPUivNZ38hdOCBQaciww3BYgxWiMwkPeNq2
8A5E6DAlRa0lENhS16NKSc+D3OEPfs21QyACKNWlaxx+iU5t+JBYhhly3vKIOAPL
v/7tfIRxLXM99KRp7l1mww42lZ2e6k37vjFTHqwGMQ8zm323fO1T/w51KwKBgQDL
3is0RSFZTnUbZc03ItDP2qyN5Grp6532SKrceJA/z9sKgiaFUq7tvTG1hBuRQFbJ
PEkL1QU7VgyRmkV2CcSomTQWguIW2mRjmOhIldj2uKcwnpi/mLewtQL4oUXaSm4j
wVkhF6ruwwQ+lvnm9YwbBzCbb/HCkDh/CNVxKf2IgwKBgQCRi9n4VSRulbAkd53H
8ZfH5gpftf/DwtEoTsjHVLtxMtmLBecrridtr+CAM+mMrpQWRHyTajFQ/XT8Prts
Nb5+0rf1UkVa/mvWoZm0/Q9dBSiSvUyRnVjSKYBV8f+2MzeXNOprvR/id5u362s/
JhLAQI5TTwmN/vyep5nl1Nz9Aw==
-----END PRIVATE KEY-----
`
	FakeCert = `-----BEGIN CERTIFICATE-----
MIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJUGFsbyBBbHRvMQ8wDQYDVQQK
DAZWTVdhcmUxDzANBgNVBAsMBkFudHJlYTESMBAGA1UEAwwJMTI3LjAuMC4xMB4X
DTIyMTIwMTAxNTc1OFoXDTI1MDgyNzAxNTc1OFowbDELMAkGA1UEBhMCVVMxEzAR
BgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVBhbG8gQWx0bzEPMA0GA1UECgwG
Vk1XYXJlMQ8wDQYDVQQLDAZBbnRyZWExEjAQBgNVBAMMCTEyNy4wLjAuMTCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO9rhYMa/lqdR7v/fnfsE9dah1dS
P8zPrvXEUZI/G2YqKSIhbR6V87K3fn9KKE0IGl+kihEfSm+5JEwF8DVM4POKAf8j
m8AWG7lUn1Fpw9ISFOsfBa4E7XBc6rsdXDhRNvBGfx2C0hyEqqtyj4FrQpUAehmb
e0XC/oxBgHNWXMqWdSGLp8lN7Y5seepX128A6C8S2qlA3gHKnDsRaLSHv6XleMyc
n6UrJJgOwnTR/xUuwb3VJ2vwt2zU/eydn5Oge51R1Ib+uO59EFyzivwu4Vk4eYmN
7KYBVFt2VpSZ6m4vF0UrBifoTXJ7DCQNfDU7+JJEJfiFJq0H2QlSiGTcrk0CAwEA
AaMTMBEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAmRy2vTfq
wPx83CfbmZruSbzuCCzF7azyvqiMjHCcjURGTzfKOlbmkC+D9QOLUZuKxHmy9bHe
sIkdr7zHRv4t8kvxMWwZcKrX9AIDY5ep8RxnPeJhccoiqDflOZf6LoSKjo7xj+ID
2gEnrOz2QP7KYqbOy7Yw7IdkE0dROV+kOW7BRfE1bI81lU1f4XsU+aEQxTohmyTs
JcE98zrI0O2V0JNpptQedIbckvsjQdN3cK3xhWcuswD6y/2mER+/uNZtNFc+rlR6
YulXOlffLizjKXCrIqg8xvanVzK0HY2iDhzXXzwdv6bSQ0mTCk/sv+v5owXONqWV
OoD2d49OYknKMw==
-----END CERTIFICATE-----
`
	FakeClientKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9FdUYGqqZOdfE
q9UnikvJgA/6vz1Ivt8OgxoZCBFpwt2cRFB+FWMw2phn9M2GiPqj6k47GGZcH597
9oo5iSAkuJNn4zWJ2xqyF04J98I3+T3pZOSt9FjK4vYvHH8WHLouTY89ydJy1/Td
Wp7Ph9YOM68Ce88wFIbIwpnYOatbF0U7Tz8mjxJsCUhH8loJ6SPghmtXK0yjTmCt
0RxFp5JIRJNg90rvp9PkQuE6u3xInUk6rJTTGD4U947AiRl4ValpID/V73BBJ5M8
6/BudSlmKe3XdLtCgunnEXKCDT2V3lRV8WyQX8G3T+7LJR4FQ/lvyAWKxm1NJqK3
3MlAaehjAgMBAAECggEAMcoS76Lt8yUJDO+WVDAVXrzK+GLtFz+zapXZBGhcdXXr
dt+CNoEZOl8FLLKIf/mHziu/Z843/eAR1cmIgjf6b9Dud7ebfG5mbCi40uUbjjOi
OtfnY2rpCpuS6breOAtedxzTMBj5wmXdQ4A+OzVwhxLS7Zt+ZhGxoCGl8wrUdUqK
Naby86EjBhNEO67PORGjTHKSGSZ647YXC7w7Lt8Q/37Tg08WsnPvadPJNbxKu5xW
l4SFPz+n3KSu1Mh5xz5guePtm45mfFU7BTJOxoeGBlN/xkVkXkoLORZsnjrum7fX
LBD8vhb4pkPzYmSRllQpNF1diVZdBakx95ptZkbIoQKBgQDsRxG4huL6GQMX+Nn6
UP/EHHO1W9Qb+2NCRqyfJVnL2MZ0HVwgjZg2pvWBezUto+upyqwfp2LTfxLd1ylQ
c6HHfbDcCGuTDvgTxoDUbUWpnPOcPaBL9IeKKS6iCHftOdqO3LpIckG4Ekec7i00
b+Ej+1t9z5J/P6fvBzv/Hq1CcwKBgQDM3lPMZZvEboXsrdAwum1DQKulpzC9ALu2
C1tkh2pGNksPuvTAWjgOIkzmFQnWmoBeeqa95KcOCwikm1rK4HlvTcsaw9uQulOV
zA2uhyq21toqO78fdHTn68oTHe1cAn8QIyDJyfNGBI7jpvEPJWsl6N3lujmqYIkb
QMUHxhYWUQKBgGMnxBELUk+glYLG5Ts+KMe1JP3UBqSjj9ktbZ3v/8ojM81g0Nu8
cEdnM5peCUgZBXog2rEB/uBA8Lr2Y5kmnZrpbYI5amOxoXwzDreXD+gJPNaxqgaW
HRdnBvHq2eFNKSJRET/76waDbVg3P/NEjFgcUR3wMUuDfEc8YvpCdnVvAoGAeXXq
yskHE+vO/OaEAw/UTcYevgSksbmokKKlGbHrQRtZX0chapVSnJabbuHURmatatZe
20CgBoRmKGlu5880T9gYbZLnLyQ5ABvNlMbQfTxediGcC4MY+JNj5/ebTSyxtpiN
DPXthHqZWMEWNDukDgLE5DmHjMrVHtJEvnojiDECgYA16YbXqL5vhFKjN6ETjt9G
XDtReiJJY7BLayFl0M3DFqAdOpn00JoVt5W04OmJ/38Bsqm46GNbc5AVrvgd8ABM
kzaGFdGZRU4ziYvkGGWruNHf+rU7Fm/SUJU81bEeq3tHiepKe91CSoFGAbq6PyLK
OlHhpQfqDW7p8sjHOFji5g==
-----END PRIVATE KEY-----
`
	FakeClientCert = `-----BEGIN CERTIFICATE-----
MIIDPzCCAiegAwIBAgIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJUGFsbyBBbHRvMQ8wDQYDVQQK
DAZWTVdhcmUxDzANBgNVBAsMBkFudHJlYTESMBAGA1UEAwwJMTI3LjAuMC4xMB4X
DTIyMTIwMTE4NTExOVoXDTI1MDgyNzE4NTExOVowRTELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0V1Rgaqpk518Sr
1SeKS8mAD/q/PUi+3w6DGhkIEWnC3ZxEUH4VYzDamGf0zYaI+qPqTjsYZlwfn3v2
ijmJICS4k2fjNYnbGrIXTgn3wjf5Pelk5K30WMri9i8cfxYcui5Njz3J0nLX9N1a
ns+H1g4zrwJ7zzAUhsjCmdg5q1sXRTtPPyaPEmwJSEfyWgnpI+CGa1crTKNOYK3R
HEWnkkhEk2D3Su+n0+RC4Tq7fEidSTqslNMYPhT3jsCJGXhVqWkgP9XvcEEnkzzr
8G51KWYp7dd0u0KC6ecRcoINPZXeVFXxbJBfwbdP7sslHgVD+W/IBYrGbU0morfc
yUBp6GMCAwEAAaMTMBEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOC
AQEADvuN8Hyb0nMm1X53yvTTOlyd+ubVqHznP/zXdliB3CoAQxbFUAW8j+Mx+5tf
phCZGgBkzTW44pWM6wNOcxLfNR7mOHDe/cea7o7LRIDCPNhfxgJMfdbjAaAgh/wT
Je0foNPlSu32EI0TMJhK13ABW4ETwOpPsNGmaZkrMpUMtZ37/FRXjUm3IqSHj9B9
Zs93ug69N6lkX1860F0ynzYNDBXAwuJop+2y8J8/jKeSSFR5ZrPg/Yq+mypGodN7
KNy9fooCVMYOkFVLWDm9dha1G8GIEozuY5J7JrXLA2RvWxEuGbKgdbmBWW76pRTZ
Uypfy643oc08jjQ5Pkh+aavtBg==
-----END CERTIFICATE-----
`
	FakeKey2 = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIERk8ms6LU+Anq+cWg9pbfJ3KbXmWdjYaWKdMZKBV4sf
-----END PRIVATE KEY-----
`
	FakeCert2 = `-----BEGIN CERTIFICATE-----
MIICRTCCAS2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzET
MBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJUGFsbyBBbHRvMQ8wDQYDVQQK
DAZWTVdhcmUxDzANBgNVBAsMBkFudHJlYTESMBAGA1UEAwwJMTI3LjAuMC4xMB4X
DTIyMTIwMTE5NDcyM1oXDTI1MDgyNzE5NDcyM1owRTELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDAqMAUGAytlcAMhALd3wi0SdLOLekhVku3hteD1PyjoxQVEU4mo3i/4zkTT
oxMwETAPBgNVHREECDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQAzCSjQ2Pq7
FDmlOm8ZQgp3ks8MdUO9cl0L+s4z87Paz4/mk/LlT5yNgNNAZFZza0pTVpR6gwh/
v22G8IAUgtr2rAkgI1FLkR6/nWibT5/fwpPXGxQ1jm2lz8+ofbhrSg+qsFf0SfAE
TPSeSZ/Ubw7YoTduGDMq7i43o/DcaF/iwTNu/XxTZhRYDuyX7HOL7mkrvtvHLQJ0
1pWZl/QlvfocX3kn+PES8FqkIfWsoX1xfP3awIryUEvX+Y20NRqtwJBJId1I/xVb
M9VyC49e+obZw9pmkS/BFkIpTi82wKNnRtk71MSc2eXaCDPUwEcKatS+T/XxvsoU
wzvYQtp9CSqd
-----END CERTIFICATE-----
`
)

var (
	validFrom = time.Now()
	maxAge    = time.Hour * 24 * 365 // one year self-signed certs
)

// We also provide these utility functions to generate test certificates dynamically.

type CertificateOption func(*x509.Certificate)

func AddDNSName(name string) CertificateOption {
	return func(cert *x509.Certificate) {
		cert.DNSNames = append(cert.DNSNames, name)
	}
}

func AddIPAddress(addr net.IP) CertificateOption {
	return func(cert *x509.Certificate) {
		cert.IPAddresses = append(cert.IPAddresses, addr)
	}
}

func GenerateCACert(options ...CertificateOption) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("test-ca@%d", time.Now().Unix()),
		},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(maxAge),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	for _, option := range options {
		option(cert)
	}
	// generate private key for CA
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	// generate CA certificate
	caCert, err := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM := bytes.Buffer{}
	pem.Encode(&caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert,
	})

	return cert, caKey, caPEM.Bytes(), err
}

func randSerialNumberOrDie() *big.Int {
	max := big.NewInt(math.MaxUint32)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic("Error when generating random cert serial number")
	}
	return n
}

func GenerateClientCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, options ...CertificateOption) ([]byte, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: randSerialNumberOrDie(),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("client-certificate@%d", time.Now().Unix()),
		},
		NotBefore:   validFrom,
		NotAfter:    validFrom.Add(maxAge),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	for _, option := range options {
		option(cert)
	}
	// generate private key for certificate
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// sign the certificate using CA certificate and key
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := bytes.Buffer{}
	pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certKeyPEM := bytes.Buffer{}
	pem.Encode(&certKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM.Bytes(), certKeyPEM.Bytes(), nil
}

func GenerateServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, options ...CertificateOption) ([]byte, []byte, error) {
	cert := &x509.Certificate{
		SerialNumber: randSerialNumberOrDie(),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("server-certificate@%d", time.Now().Unix()),
		},
		NotBefore:   validFrom,
		NotAfter:    validFrom.Add(maxAge),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{},
		DNSNames:    []string{},
	}
	for _, option := range options {
		option(cert)
	}
	// generate private key for certificate
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	// sign the certificate using CA certificate and key
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := bytes.Buffer{}
	pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certKeyPEM := bytes.Buffer{}
	pem.Encode(&certKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM.Bytes(), certKeyPEM.Bytes(), nil
}
