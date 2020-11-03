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
	assert.Equal(t, 0, len(globalRegistryByID))
	assert.Equal(t, 0, len(globalRegistryByName))
	LoadRegistry()
	assert.NotEmpty(t, globalRegistryByName[IANAEnterpriseID])
	assert.NotEmpty(t, globalRegistryByName[AntreaEnterpriseID])
	assert.NotEmpty(t, globalRegistryByName[IANAReversedEnterpriseID])
	assert.NotEmpty(t, globalRegistryByID[IANAEnterpriseID])
	assert.NotEmpty(t, globalRegistryByID[AntreaEnterpriseID])
	assert.NotEmpty(t, globalRegistryByID[IANAReversedEnterpriseID])
}

func TestGetInfoElement(t *testing.T) {
	LoadRegistry()
	var expectedIE *entities.InfoElement
	ie, error := GetInfoElement("ingressInterfaceTest", IANAEnterpriseID)
	assert.Equal(t, expectedIE, ie, "GetIANAInfoElement did not return correct value.")
	assert.NotEqual(t, nil, error, "GetIANAInfoElement should return error if cannot find InfoElement.")

	ie, error = GetInfoElement("ingressInterface", IANAEnterpriseID)
	assert.Equal(t, "ingressInterface", ie.Name, "GetIANAInfoElement did not return correct value.")
	assert.Equal(t, nil, error, "GetIANAInfoElement should not return error if InfoElement exists.")
}

func TestGetIANAReverseIE(t *testing.T) {
	LoadRegistry()
	// InfoElement does not exist in the registry
	reverseIE, error := getIANAReverseInfoElement("sourcePodName")
	assert.NotEqual(t, nil, error, "GetIANAReverseIE should return error when ie does not exist.")
	// InfoElement is not reversible
	reverseIE, error = getIANAReverseInfoElement("flowKeyIndicator")
	assert.NotEqual(t, nil, error, "GetIANAReverseIE should return error when ie is not reversible.")
	// reverse InfoElement exists
	reverseIE, error = getIANAReverseInfoElement("deltaFlowCount")
	assert.Equal(t, "reverseDeltaFlowCount", reverseIE.Name, "GetIANAReverseIE does not return correct reverse ie.")
	assert.Equal(t, IANAReversedEnterpriseID, reverseIE.EnterpriseId, "GetIANAReverseIE does not return correct reverse ie.")
}

func TestGetInfoElementFromID(t *testing.T) {
	LoadRegistry()
	// InfoElement does not exist
	ie, err := GetInfoElementFromID(1, 1)
	assert.NotEqual(t, nil, err, "TestGetInfoElementFromID should return error when ie does not exist.")
	// InfoElement exists (reverse InfoElement)
	ie, err = GetInfoElementFromID(1, IANAReversedEnterpriseID)
	assert.Equal(t, "reverseOctetDeltaCount", ie.Name, "TestGetInfoElementFromID does not return correct reverse ie.")
	assert.Equal(t, IANAReversedEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct reverse ie.")
	// InfoElement exists (IANA InfoElement)
	ie, err = GetInfoElementFromID(1, IANAEnterpriseID)
	assert.Equal(t, "octetDeltaCount", ie.Name, "TestGetInfoElementFromID does not return correct IANA ie.")
	assert.Equal(t, IANAEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct IANA ie.")
	// InfoElement exists (Antrea InfoElement)
	ie, err = GetInfoElementFromID(105, AntreaEnterpriseID)
	assert.Equal(t, "destinationNodeName", ie.Name, "TestGetInfoElementFromID does not return correct Antrea ie.")
	assert.Equal(t, AntreaEnterpriseID, ie.EnterpriseId, "TestGetInfoElementFromID does not return correct Antrea ie.")
}
