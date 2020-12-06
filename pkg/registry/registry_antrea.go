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

package registry

import (
	"github.com/vmware/go-ipfix/pkg/entities"
)

// AUTO GENERATED, DO NOT CHANGE

func loadAntreaRegistry() {
	registerInfoElement(*entities.NewInfoElement("sourcePodNamespace", 100, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourcePodName", 101, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodNamespace", 102, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationPodName", 103, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("sourceNodeName", 104, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationNodeName", 105, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationClusterIPv4", 106, 18, 56506, 4), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationClusterIPv6", 107, 19, 56506, 16), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationServicePort", 108, 2, 56506, 2), 56506)
	registerInfoElement(*entities.NewInfoElement("destinationServicePortName", 109, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyName", 110, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyNamespace", 111, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyName", 112, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyNamespace", 113, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyUID", 114, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyType", 115, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("ingressNetworkPolicyRulePriority", 116, 2, 56506, 2), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyUID", 117, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyType", 118, 13, 56506, 65535), 56506)
	registerInfoElement(*entities.NewInfoElement("egressNetworkPolicyRulePriority", 119, 2, 56506, 2), 56506)
	registerInfoElement(*entities.NewInfoElement("packetTotalCountFromSourceNode", 120, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetTotalCountFromSourceNode", 121, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetDeltaCountFromSourceNode", 122, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetDeltaCountFromSourceNode", 123, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketTotalCountFromSourceNode", 124, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetTotalCountFromSourceNode", 125, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketDeltaCountFromSourceNode", 126, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetDeltaCountFromSourceNode", 127, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetTotalCountFromDestinationNode", 128, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetTotalCountFromDestinationNode", 129, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("packetDeltaCountFromDestinationNode", 130, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("octetDeltaCountFromDestinationNode", 131, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketTotalCountFromDestinationNode", 132, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetTotalCountFromDestinationNode", 133, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reversePacketDeltaCountFromDestinationNode", 134, 4, 56506, 8), 56506)
	registerInfoElement(*entities.NewInfoElement("reverseOctetDeltaCountFromDestinationNode", 135, 4, 56506, 8), 56506)
}
