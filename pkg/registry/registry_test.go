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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vmware/go-ipfix/pkg/entities"
)

func TestNewIanaRegistry(t *testing.T) {
	reg := NewIanaRegistry()
	assert.Equal(t, 0, len(reg.registry), "IANA Registry did not initialized correctly.")
}

func TestNewAntreaRegistry(t *testing.T) {
	reg := NewAntreaRegistry()
	assert.Equal(t, 0, len(reg.registry), "Antrea Registry did not initialized correctly.")
}

func TestIanaRegistryGetInfoElement(t *testing.T) {
	reg := NewIanaRegistry()
	ie, error := reg.GetInfoElement("ingressInterface")
	assert.Equal(t, entities.InfoElement{}, *ie, "IANA registry GetInfoElement did not return correct value.")
	assert.NotEqual(t, nil, error, "IANA registry GetInfoElement should return error if cannot find InfoElement.")
	reg.registerInfoElement(entities.InfoElement{"ingressInterface", 104, 13, 55829, 65535})
	ie, error = reg.GetInfoElement("ingressInterface")
	assert.Equal(t, "ingressInterface", ie.Name, "IANA registry GetInfoElement did not return correct value.")
	assert.Equal(t, nil, error, "IANA registry GetInfoElement should not return error if InfoElement exists.")
}

func TestIanaRegistryLoadRegistry(t *testing.T) {
	reg := NewIanaRegistry()
	reg.LoadRegistry()
	ie, error := reg.GetInfoElement("ipNextHopIPv6Address")
	errorMsg := "IANA registry LoadRegistry did not load registry correctly."
	assert.Equal(t, "ipNextHopIPv6Address", ie.Name, errorMsg)
	assert.Equal(t, nil, error, errorMsg)
	ie, error = reg.GetInfoElement("sourcePodName")
	assert.Equal(t, entities.InfoElement{}, *ie, errorMsg)
	assert.NotEqual(t, nil, error, errorMsg)
}

func TestIanaRegistryGetReverseInfoElement(t *testing.T) {
	reg := NewIanaRegistry()
	reg.LoadRegistry()
	// InfoElement does not exist in the registry
	reverseIE, error := reg.GetReverseInfoElement("sourcePodName")
	assert.NotEqual(t, nil, error, "IANA registry GetReverseInfoElement should return error when ie does not exist.")
	// InfoElement is not reversible
	reverseIE, error = reg.GetReverseInfoElement("flowKeyIndicator")
	assert.NotEqual(t, nil, error, "IANA registry GetReverseInfoElement should return error when ie is not reversible.")
	// reverse InfoElement exists
	reverseIE, error = reg.GetReverseInfoElement("deltaFlowCount")
	assert.Equal(t, "reverse_DeltaFlowCount", reverseIE.Name, "IANA registry GetReverseInfoElement does not return correct reverse ie.")
	assert.Equal(t, reversePen, reverseIE.EnterpriseId, "IANA registry GetReverseInfoElement does not return correct reverse ie.")
}

func TestAntreaRegistryGetInfoElement(t *testing.T) {
	reg := NewAntreaRegistry()
	ie, error := reg.GetInfoElement("sourceNodeName")
	assert.Equal(t, entities.InfoElement{}, *ie, "Antrea registry GetInfoElement did not return correct value.")
	assert.NotEqual(t, nil, error, "Antrea registry GetInfoElement should return error if cannot find InfoElement.")
	reg.registerInfoElement(entities.InfoElement{"sourceNodeName", 104, 13, 55829, 65535})
	ie, error = reg.GetInfoElement("sourceNodeName")
	assert.Equal(t, "sourceNodeName", ie.Name, "Antrea registry GetInfoElement did not return correct value.")
	assert.Equal(t, nil, error, "Antrea registry GetInfoElement should not return error if InfoElement exists.")
}

func TestAntreaRegistryLoadRegistry(t *testing.T) {
	reg := NewAntreaRegistry()
	reg.LoadRegistry()
	ie, error := reg.GetInfoElement("destinationClusterIP")
	errorMsg := "Antrea registry LoadRegistry did not load registry correctly."
	assert.Equal(t, "destinationClusterIP", ie.Name, errorMsg)
	assert.Equal(t, nil, error, errorMsg)
	ie, error = reg.GetInfoElement("sourceMacAddress")
	assert.Equal(t, entities.InfoElement{}, *ie, errorMsg)
	assert.NotEqual(t, nil, error, errorMsg)
}

func TestAntreaRegistryGetReverseInfoElement(t *testing.T) {
	reg := NewAntreaRegistry()
	reg.LoadRegistry()
	// InfoElement does not exist in the registry
	reverseIE, error := reg.GetReverseInfoElement("flowDirection")
	assert.NotEqual(t, nil, error, "Antrea registry GetReverseInfoElement should return error when ie does not exist.")
	// reverse InfoElement exists
	reverseIE, error = reg.GetReverseInfoElement("destinationClusterIP")
	assert.Equal(t, "reverse_DestinationClusterIP", reverseIE.Name, "Antrea registry GetReverseInfoElement does not return correct reverse ie.")
	assert.Equal(t, reversePen, reverseIE.EnterpriseId, "Antrea registry GetReverseInfoElement does not return correct reverse ie.")
}
