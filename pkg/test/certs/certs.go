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

package certs

import (
	"bytes"
	"crypto/ed25519"
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

var (
	validFrom = time.Now()
	maxAge    = time.Hour * 24 * 365 // one year self-signed certs
)

// We provide these utility functions to generate test certificates dynamically.

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

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func GenerateServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, ed25519Key bool, options ...CertificateOption) ([]byte, []byte, error) {
	var err error
	var priv any
	// generate private key for certificate
	if ed25519Key {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	} else {
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
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
	// sign the certificate using CA certificate and key
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, publicKey(priv), caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := bytes.Buffer{}
	pem.Encode(&certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to marshal private key: %w", err)
	}
	certKeyPEM := bytes.Buffer{}
	pem.Encode(&certKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	return certPEM.Bytes(), certKeyPEM.Bytes(), nil
}

// We generate some certificate material ahead of time for integration tests.

var (
	FakeCACert                    []byte
	FakeKey, FakeCert             []byte
	FakeKey2, FakeCert2           []byte
	FakeClientKey, FakeClientCert []byte
)

func init() {
	caCert, caKey, caCertPEM, err := GenerateCACert()
	if err != nil {
		panic(err)
	}
	FakeCACert = caCertPEM

	FakeCert, FakeKey, err = GenerateServerCert(caCert, caKey, false /* RSA */, AddIPAddress(net.ParseIP("127.0.0.1")))
	if err != nil {
		panic(err)
	}

	FakeCert2, FakeKey2, err = GenerateServerCert(caCert, caKey, true /* ED25519 */, AddIPAddress(net.ParseIP("127.0.0.1")))
	if err != nil {
		panic(err)
	}

	FakeClientCert, FakeClientKey, err = GenerateClientCert(caCert, caKey)
	if err != nil {
		panic(err)
	}
}
