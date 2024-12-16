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

//go:build integration
// +build integration

package test

import (
	"net"
	"sync"
	"testing"

	"github.com/IBM/sarama"
	saramamock "github.com/IBM/sarama/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vmware/go-ipfix/pkg/collector"
	"github.com/vmware/go-ipfix/pkg/kafka/producer"
	convertortest "github.com/vmware/go-ipfix/pkg/kafka/producer/convertor/test"
)

var (
	msg1InBytes = []byte{0x0, 0x0, 0x0, 0x68, 0x8, 0xca, 0xe0, 0xcb, 0xee, 0x5, 0x18, 0x1, 0x20,
		0x88, 0xd9, 0xe7, 0xd7, 0x4, 0x28, 0xf0, 0xe0, 0xe7, 0xd7, 0x4, 0x32, 0x8, 0x31,
		0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x8, 0x31, 0x30, 0x2e, 0x30, 0x2e,
		0x30, 0x2e, 0x32, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6, 0x58, 0xa0, 0x6,
		0x60, 0x80, 0xea, 0x30, 0x68, 0xf4, 0x3, 0x78, 0xac, 0x2, 0x80, 0x1, 0xe0, 0xa7,
		0x12, 0x88, 0x1, 0x96, 0x1, 0x9a, 0x1, 0x4, 0x70, 0x6f, 0x64, 0x31, 0xca, 0x1, 0x8,
		0x31, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x33, 0x8a, 0x2, 0x9, 0x31, 0x32, 0x37,
		0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x90, 0x2, 0x83, 0x25}
	msg2InBytes = []byte{0x0, 0x0, 0x0, 0x63, 0x8, 0xca, 0xe0, 0xcb, 0xee, 0x5, 0x18, 0x1, 0x20,
		0x88, 0xd9, 0xe7, 0xd7, 0x4, 0x28, 0xc0, 0xf0, 0xe7, 0xd7, 0x4, 0x32, 0x8, 0x31,
		0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x8, 0x31, 0x30, 0x2e, 0x30, 0x2e,
		0x30, 0x2e, 0x32, 0x40, 0xd2, 0x9, 0x48, 0xae, 0x2c, 0x50, 0x6, 0x58, 0xe8, 0x7,
		0x60, 0xc0, 0x84, 0x3d, 0x68, 0xf4, 0x3, 0x78, 0x90, 0x3, 0x80, 0x1, 0x80, 0xb5,
		0x18, 0x88, 0x1, 0xc8, 0x1, 0xb2, 0x1, 0x4, 0x70, 0x6f, 0x64, 0x32, 0xca, 0x1, 0x7,
		0x30, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x8a, 0x2, 0x9, 0x31, 0x32, 0x37, 0x2e,
		0x30, 0x2e, 0x30, 0x2e, 0x31}
)

func TestCollectorToProducer(t *testing.T) {
	// Initialize collecting process
	cpInput := collector.CollectorInput{
		Address:       "127.0.0.1:0",
		Protocol:      "udp",
		MaxBufferSize: 1024,
		TemplateTTL:   0,
		IsEncrypted:   false,
		ServerCert:    nil,
		ServerKey:     nil,
	}
	cp, _ := collector.InitCollectingProcess(cpInput)
	// Create a mock Kafka producer
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = sarama.DefaultVersion
	kafkaConfig.Producer.Return.Successes = true
	kafkaConfig.Producer.Return.Errors = true

	testInput := producer.ProducerInput{
		KafkaLogSuccesses:    false,
		KafkaTopic:           "test-flow-msgs",
		ProtoSchemaConvertor: convertortest.NewFlowType1Convertor(),
		KafkaVersion:         sarama.DefaultVersion,
	}
	mockSaramaProducer := saramamock.NewAsyncProducer(t, kafkaConfig)
	kafkaProducer, err := producer.NewKafkaProducer(testInput)
	require.NoError(t, err)
	kafkaProducer.SetSaramaProducer(mockSaramaProducer)

	go cp.Start()
	waitForCollectorReady(t, cp)
	collectorAddr := cp.GetAddress()
	address, err := net.ResolveUDPAddr(collectorAddr.Network(), collectorAddr.String())
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := net.DialUDP("udp", nil, address)
		if err != nil {
			t.Errorf("UDP Collecting Process did not start correctly.")
			return
		}
		defer conn.Close()
		// Using the packets from collector_intermediate_test.go
		conn.Write(templatePacketIPv4)
		conn.Write(dataPacket1IPv4)
		conn.Write(dataPacket2IPv4)
	}()

	go func() {
		mockSaramaProducer.ExpectInputAndSucceed()
		mockSaramaProducer.ExpectInputAndSucceed()
		kafkaProducer.PublishIPFIXMessages(cp.GetMsgChan())
	}()

	kafkaMsg1 := <-mockSaramaProducer.Successes()
	kafkaMsg1InBytes, _ := kafkaMsg1.Value.Encode()
	assert.Equalf(t, msg1InBytes, kafkaMsg1InBytes, "kafka msg should be equal to expected bytes")
	kafkaMsg2 := <-mockSaramaProducer.Successes()
	kafkaMsg2InBytes, _ := kafkaMsg2.Value.Encode()
	assert.Equalf(t, msg2InBytes, kafkaMsg2InBytes, "kafka msg should be equal to expected bytes")

	wg.Wait() // making sure client connection is closed before stopping collector
	cp.Stop()
	if err := mockSaramaProducer.Close(); err != nil {
		t.Fatal(err)
	}
}
