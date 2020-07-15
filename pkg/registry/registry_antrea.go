// Copyright 2020 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"github.com/vmware/go-ipfix/pkg/entities"
)

// AUTO GENERATED, DO NOT CHANGE

func (registry *antreaRegistry) LoadRegistry() {
	registry.registerInfoElement(*entities.NewInfoElement("sourcePodNamespace", 100, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("sourcePodName", 101, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("destinationPodNamespace", 102, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("destinationPodName", 103, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("sourceNodeName", 104, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("destinationNodeName", 105, 13, 55829, 65535))
	registry.registerInfoElement(*entities.NewInfoElement("destinationClusterIP", 106, 18, 55829, 4))
	registry.registerInfoElement(*entities.NewInfoElement("destinationServicePort", 107, 2, 55829, 2))
}
