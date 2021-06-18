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

package producer

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"testing"

	"github.com/Shopify/sarama"
	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/test"
)

func TestInitKafkaProducerWithTLS(t *testing.T) {
	caCertFile := createTmpFileAndWrite(t, test.FakeCACert, "ca-")
	certFile := createTmpFileAndWrite(t, test.FakeCert, "cert-")
	keyFile := createTmpFileAndWrite(t, test.FakeKey, "key-")
	defer closeTmpFile(t, caCertFile)
	defer closeTmpFile(t, certFile)
	defer closeTmpFile(t, keyFile)

	serverTLSConfig, err := setupTLSConfig(caCertFile.Name(), certFile.Name(), keyFile.Name(), false)
	assert.NoError(t, err)

	doListenerTLSTest(t, serverTLSConfig, test.FakeCACert, test.FakeClientCert, test.FakeClientKey)
}

func doListenerTLSTest(t *testing.T, serverTLSConfig *tls.Config, caCert, clientCert, clientKey string) {
	seedListener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig)
	if err != nil {
		t.Fatal("cannot open listener", err)
	}
	seedBroker := sarama.NewMockBrokerListener(t, 1, seedListener)
	defer seedBroker.Close()

	seedBroker.Returns(new(sarama.MetadataResponse))

	caCertFile := createTmpFileAndWrite(t, test.FakeCACert, "ca-")
	certFile := createTmpFileAndWrite(t, test.FakeClientCert, "clientCert-")
	keyFile := createTmpFileAndWrite(t, test.FakeClientKey, "clientKey-")
	defer closeTmpFile(t, caCertFile)
	defer closeTmpFile(t, certFile)
	defer closeTmpFile(t, keyFile)

	testInput := ProducerInput{
		KafkaLogSuccesses:  false,
		KafkaCAFile:        caCertFile.Name(),
		KafkaTLSCertFile:   certFile.Name(),
		KafkaTLSKeyFile:    keyFile.Name(),
		KafkaTLSEnabled:    true,
		KafkaTLSSkipVerify: false,
		KafkaBrokers:       []string{seedBroker.Addr()},
		KafkaVersion:       sarama.MinVersion,
	}
	kafkaProducer := KafkaProducer{
		input: testInput,
	}
	err = kafkaProducer.InitSaramaProducer()
	assert.NoError(t, err)
	if err == nil {
		err = kafkaProducer.producer.Close()
		assert.NoError(t, err)
	}
}

func createTmpFileAndWrite(t *testing.T, content, pattern string) *os.File {
	tmpFile, err := ioutil.TempFile(os.TempDir(), pattern)
	if err != nil {
		t.Fatal("Cannot create temporary file", err)
	}

	// Example writing to the file
	text := []byte(content)
	if _, err = tmpFile.Write(text); err != nil {
		t.Fatal("Failed to write to temporary file", err)
	}

	return tmpFile
}

func closeTmpFile(t *testing.T, file *os.File) {
	defer os.Remove(file.Name())

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
