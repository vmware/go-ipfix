// Copyright 2020 go-ipfix Authors
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
	"github.com/srikartati/go-ipfixlib/pkg/entities"
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
