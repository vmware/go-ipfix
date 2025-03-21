// Copyright 2021 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http: //www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

syntax = "proto3";

package antrea_io.antrea.pkg.flowaggregator.kafka.protobuf;

option go_package = "pkg/flowaggregator/kafka/protobuf";

// Antrea proto schema is compatible with go-ipfix Kafka consumer.
message AntreaFlowMsg {
  // From the header of IPFIX Message.
  uint32 TimeReceived = 1;
  uint32 SequenceNumber = 2;
  uint32 ObsDomainID = 3;
  string ExportAddress = 33;

  // Fields of flow record.
  uint32 TimeFlowStartInSecs = 4;
  uint32 TimeFlowEndInSecs = 5;
  uint64 TimeFlowStartInMilliSecs = 27;
  uint32 TimeFlowEndInMilliSecs = 28;

  // 5-tuple of flows
  string SrcIP = 6;
  string DstIP = 7;
  uint32 SrcPort = 8;
  uint32 DstPort = 9;
  uint32 Proto = 10;

  // Statistics of flow in original and reverse directions.
  uint64 PacketsTotal = 11;
  uint64 BytesTotal = 12;
  uint64 PacketsDelta = 13;
  uint64 BytesDelta = 14;
  uint64 ReversePacketsTotal = 15;
  uint64 ReverseBytesTotal = 16;
  uint64 ReversePacketsDelta = 17;
  uint64 ReverseBytesDelta = 18;

  // Kubernetes metadata
  string SrcPodName = 19;
  string SrcPodNamespace = 20;
  string SrcNodeName = 21;
  string DstPodName = 22;
  string DstPodNamespace = 23;
  string DstNodeName = 24;
  string DstClusterIP = 25;
  uint32 DstServicePort = 34;
  string DstServicePortName = 26;
  string IngressPolicyName = 29;
  string IngressPolicyNamespace = 30;
  string EgressPolicyName = 31;
  string EgressPolicyNamespace = 32;
}