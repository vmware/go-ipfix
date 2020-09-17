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

func TestLoadRegistry(t *testing.T) {
	assert.Equal(t, 0, len(globalRegistry))
	assert.Equal(t, 0, len(ianaRegistry))
	assert.Equal(t, 0, len(antreaRegistry))
	LoadRegistry()

}

func TestGetIANAInfoElement(t *testing.T) {
	LoadRegistry()
	ie, error := GetIANAInfoElement("ingressInterfaceTest")
	assert.Equal(t, entities.InfoElement{}, *ie, "GetIANAInfoElement did not return correct value.")
	assert.NotEqual(t, nil, error, "GetIANAInfoElement should return error if cannot find InfoElement.")

	ie, error = GetIANAInfoElement("ingressInterface")
	assert.Equal(t, "ingressInterface", ie.Name, "GetIANAInfoElement did not return correct value.")
	assert.Equal(t, nil, error, "GetIANAInfoElement should not return error if InfoElement exists.")
}

func TestGetIANAReverseIE(t *testing.T) {
	LoadRegistry()
	// InfoElement does not exist in the registry
	reverseIE, error := GetIANAReverseIE("sourcePodName")
	assert.NotEqual(t, nil, error, "GetIANAReverseIE should return error when ie does not exist.")
	// InfoElement is not reversible
	reverseIE, error = GetIANAReverseIE("flowKeyIndicator")
	assert.NotEqual(t, nil, error, "GetIANAReverseIE should return error when ie is not reversible.")
	// reverse InfoElement exists
	reverseIE, error = GetIANAReverseIE("deltaFlowCount")
	assert.Equal(t, "reverse_DeltaFlowCount", reverseIE.Name, "GetIANAReverseIE does not return correct reverse ie.")
	assert.Equal(t, ReverseEnterpriseID, reverseIE.EnterpriseId, "GetIANAReverseIE does not return correct reverse ie.")
}

func TestGetAntreaInfoElement(t *testing.T) {
	LoadRegistry()
	ie, error := GetAntreaInfoElement("sourceNodeNameTest")
	assert.Equal(t, entities.InfoElement{}, *ie, "GetAntreaInfoElement did not return correct value.")
	assert.NotEqual(t, nil, error, "GetAntreaInfoElement should return error if cannot find InfoElement.")

	ie, error = GetAntreaInfoElement("sourceNodeName")
	assert.Equal(t, "sourceNodeName", ie.Name, "GetAntreaInfoElement did not return correct value.")
	assert.Equal(t, nil, error, "GetAntreaInfoElement should not return error if InfoElement exists.")
}

func TestGetAntreaReverseIE(t *testing.T) {
	LoadRegistry()
	// InfoElement does not exist in the registry
	reverseIE, error := GetAntreaReverseIE("flowDirection")
	assert.NotEqual(t, nil, error, "GetAntreaReverseIE should return error when ie does not exist.")
	// reverse InfoElement exists
	reverseIE, error = GetAntreaReverseIE("destinationClusterIP")
	assert.Equal(t, "reverse_DestinationClusterIP", reverseIE.Name, "GetAntreaReverseIE does not return correct reverse ie.")
	assert.Equal(t, ReverseEnterpriseID, reverseIE.EnterpriseId, "GetAntreaReverseIE does not return correct reverse ie.")
}

func TestGetInfoElementFromID(t *testing.T) {
	LoadRegistry()
	// InfoElement does not exist
	ie, err := GetInfoElementFromID(1, 1)
	assert.NotEqual(t, nil, err, "TestGetInfoElementFromID should return error when ie does not exist.")
	// InfoElement exists (reverse InfoElement)
	ie, err = GetInfoElementFromID(1, ReverseEnterpriseID)
	assert.Equal(t, "reverse_OctetDeltaCount", ie.Name, "TestGetInfoElementFromID does not return correct reverse ie.")
	assert.Equal(t, ReverseEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct reverse ie.")
	// InfoElement exists (IANA InfoElement)
	ie, err = GetInfoElementFromID(1, IANAEnterpriseID)
	assert.Equal(t, "octetDeltaCount", ie.Name, "TestGetInfoElementFromID does not return correct IANA ie.")
	assert.Equal(t, IANAEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct IANA ie.")
	// InfoElement exists (Antrea InfoElement)
	ie, err = GetInfoElementFromID(105, AntreaEnterpriseID)
	assert.Equal(t, "destinationNodeName", ie.Name, "TestGetInfoElementFromID does not return correct Antrea ie.")
	assert.Equal(t, AntreaEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct Antrea ie.")
}
