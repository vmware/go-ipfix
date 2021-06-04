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

package convertor

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/vmware/go-ipfix/pkg/entities"
)

type RegisterProtoSchema func() IPFIXToKafkaConvertor

var ProtoSchemaConvertor = map[string]RegisterProtoSchema{}

// IPFIXToKafkaConvertor is an interface to support multiple proto schema for Kafka
// producer.
type IPFIXToKafkaConvertor interface {
	// ConvertIPFIXMsgToFlowMsgs converts multiple data records in the IPFIX message
	// to flow messages for any given proto schema.
	ConvertIPFIXMsgToFlowMsgs(msg *entities.Message) []protoreflect.Message
	// ConvertIPFIXRecordToFlowMsg converts a single IPFIX record to a kafka flow
	// message for any given proto schema. Some times producers are interacting
	// with the intermediate process instead of the collector process, where only
	// the record is available.
	ConvertIPFIXRecordToFlowMsg(record entities.Record) protoreflect.Message
}
