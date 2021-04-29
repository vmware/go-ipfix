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
	"io/ioutil"
	"log"
	"os"

	"github.com/Shopify/sarama"
	"google.golang.org/protobuf/proto"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/producer/convertor"
	"github.com/vmware/go-ipfix/pkg/producer/protobuf"
)

type ProducerInput struct {
	// KafkaBrokers is a string of addresses of Kafka broker systems
	KafkaBrokers         []string
	KafkaVersion         sarama.KafkaVersion
	KafkaTopic           string
	KafkaProtoSchema     string
	KafkaTLSEnabled      bool
	KafkaCAFile          string
	KafkaTLSCertFile     string
	KafkaTLSKeyFile      string
	KafkaTLSSkipVerify   bool
	KafkaLogErrors       bool
	KafkaLogSuccesses    bool
	EnableSaramaDebugLog bool
}

type KafkaProducer struct {
	producer             sarama.AsyncProducer
	input                ProducerInput
	protoSchemaConvertor convertor.IPFIXToKafkaConvertor
}

func NewKafkaProducer(input ProducerInput) *KafkaProducer {
	return &KafkaProducer{
		input:                input,
		protoSchemaConvertor: convertor.ProtoSchemaConvertor[input.KafkaProtoSchema](),
	}
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

	// Capturing errors from Kafka sarama client
	if kp.input.KafkaLogErrors {
		go func() {
			for msg := range kp.producer.Errors() {
				klog.Error(msg)
			}
		}()
	}

	return nil
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

		caCert, err := ioutil.ReadFile(caFile)
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
func (kp *KafkaProducer) SendFlowMessage(msg *protobuf.FlowMessage, kafkaDelimitMsgWithLen bool) {
	bytes, err := proto.Marshal(msg)
	if err != nil {
		klog.Errorf("Error when encoding flow message: %v", err)
		return
	}
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
		klog.V(2).Infof("Sent the message successfully: %v", kafkaMsg)
	}

}

// Publish takes in a message channel as input and converts all the messages on
// the message channel to flow messages in proto schema. This function exits when
// the input message channel is closed.
func (kp *KafkaProducer) Publish(msgCh chan *entities.Message) {
	for msg := range msgCh {
		flowMsgs := kp.protoSchemaConvertor.ConvertIPFIXMsgToFlowMsgs(msg)
		for _, flowMsg := range flowMsgs {
			kp.SendFlowMessage(flowMsg, true)
		}
	}
}
