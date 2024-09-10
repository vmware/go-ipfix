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

package producer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/IBM/sarama"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/kafka/producer/convertor"
)

type ProducerInput struct {
	// KafkaBrokers is a string of addresses of Kafka broker systems
	KafkaBrokers         []string
	KafkaVersion         sarama.KafkaVersion
	KafkaTopic           string
	KafkaTLSEnabled      bool
	KafkaCAFile          string
	KafkaTLSCertFile     string
	KafkaTLSKeyFile      string
	KafkaTLSSkipVerify   bool
	KafkaLogErrors       bool
	KafkaLogSuccesses    bool
	EnableSaramaDebugLog bool
	ProtoSchemaConvertor convertor.IPFIXToKafkaConvertor
}

type KafkaProducer struct {
	producer sarama.AsyncProducer
	input    ProducerInput
	// closeCh is required to exit the go routine that captures error messages from
	// sarama go client.
	closeCh chan struct{}
}

func NewKafkaProducer(input ProducerInput) (*KafkaProducer, error) {
	if !input.KafkaVersion.IsAtLeast(sarama.DefaultVersion) {
		return nil, fmt.Errorf("kafka version is not provided correctly")
	}
	if input.ProtoSchemaConvertor == nil {
		return nil, fmt.Errorf("requires a protoschema convertor to convert IPFIX messages into kafka flow message")
	}
	return &KafkaProducer{
		input: input,
	}, nil
}

func (kp *KafkaProducer) InitSaramaProducer() error {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Version = kp.input.KafkaVersion
	kafkaConfig.Producer.Return.Successes = kp.input.KafkaLogSuccesses
	kafkaConfig.Producer.Return.Errors = kp.input.KafkaLogErrors

	if kp.input.KafkaTLSEnabled {
		tlsConfig, err := setupTLSConfig(kp.input.KafkaCAFile, kp.input.KafkaTLSCertFile, kp.input.KafkaTLSKeyFile, kp.input.KafkaTLSSkipVerify)
		if err != nil {
			return err
		}
		kafkaConfig.Net.TLS.Config = tlsConfig
		kafkaConfig.Net.TLS.Enable = true
	}

	if kp.input.EnableSaramaDebugLog {
		sarama.Logger = log.New(os.Stderr, "[sarama] ", log.LstdFlags)
	}

	var err error
	kp.producer, err = sarama.NewAsyncProducer(kp.input.KafkaBrokers, kafkaConfig)
	if err != nil {
		return err
	}

	// Capturing errors from Kafka sarama client and publishing error messages as
	// klog error messages.
	if kp.input.KafkaLogErrors {
		kp.closeCh = make(chan struct{})
		go func() {
			for {
				select {
				case <-kp.closeCh:
					return
				case msg := <-kp.producer.Errors():
					klog.Error(msg)
				}
			}
		}()
	}

	return nil
}

func (kp *KafkaProducer) GetSaramaProducer() sarama.AsyncProducer {
	return kp.producer
}

// SetSaramaProducer is needed for only tests for setting the sarama producer as
// mock producer
func (kp *KafkaProducer) SetSaramaProducer(producer sarama.AsyncProducer) {
	kp.producer = producer
}

func setupTLSConfig(caFile, tlsCertFile, tlsKeyFile string, kafkaTLSSkipVerify bool) (*tls.Config, error) {
	var t *tls.Config

	if tlsCertFile != "" || tlsKeyFile != "" || caFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("kafka TLS load X509 key pair error: %v", err)
		}

		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("kafka TLS CA file error: %v", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		if kafkaTLSSkipVerify {
			klog.V(4).Info("kafka client TLS enabled (server certificate didn't validate)")
		} else {
			klog.V(4).Info("kafka client TLS enabled")
		}
		t = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
		}
		// #nosec G402: only applicable for testing purpose
		t.InsecureSkipVerify = kafkaTLSSkipVerify
	}

	return t, nil
}

// SendFlowMessage takes in the flow message in proto schema, encodes it and sends
// it to on the producer channel. If kafkaDelimitMsgWithLen is set to true, it will
// return  a length-prefixed encoded message.
func (kp *KafkaProducer) SendFlowMessage(msg protoreflect.Message, kafkaDelimitMsgWithLen bool) {
	bytes, err := proto.Marshal(msg.Interface())
	if err != nil {
		klog.Errorf("Error when encoding flow message: %v", err)
		return
	}
	klog.V(4).Infof("Sending the kafka message: %v", string(bytes))
	if kafkaDelimitMsgWithLen {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(bytes)))
		bytes = append(b, bytes...)
	}

	kp.producer.Input() <- &sarama.ProducerMessage{
		Topic: kp.input.KafkaTopic,
		Value: sarama.ByteEncoder(bytes),
	}
	if kp.input.KafkaLogSuccesses {
		kafkaMsg := <-kp.producer.Successes()
		klog.V(4).Infof("Sent the message successfully: %v", kafkaMsg)
	}

}

// PublishIPFIXMessages takes in a message channel as input and converts all the messages on
// the message channel to flow messages in proto schema. This function exits when
// the input message channel is closed.
func (kp *KafkaProducer) PublishIPFIXMessages(msgCh <-chan *entities.Message) {
	for msg := range msgCh {
		flowMsgs := kp.input.ProtoSchemaConvertor.ConvertIPFIXMsgToFlowMsgs(msg)
		for _, flowMsg := range flowMsgs {
			kp.SendFlowMessage(flowMsg, true)
		}
	}
}

func (kp *KafkaProducer) PublishRecord(record entities.Record) {
	flowMsg := kp.input.ProtoSchemaConvertor.ConvertIPFIXRecordToFlowMsg(record)
	kp.SendFlowMessage(flowMsg, false)
}

func (kp *KafkaProducer) Close() {
	if kp.producer == nil {
		return
	}

	var wg sync.WaitGroup
	kp.producer.AsyncClose()

	wg.Add(1)
	go func() {
		if kp.closeCh != nil {
			close(kp.closeCh)
		}
		if kp.input.KafkaLogSuccesses {
			for range kp.producer.Successes() {
				klog.Error("Unexpected message on Successes()")
			}
		}
		wg.Done()
	}()
	wg.Wait()
}
