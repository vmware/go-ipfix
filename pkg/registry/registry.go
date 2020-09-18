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
	"fmt"
	"strings"

	"github.com/vmware/go-ipfix/pkg/entities"
)

const (
	// AntreaEnterpriseID is the enterprise ID for Antrea Information Elements
	AntreaEnterpriseID uint32 = 55829
	// IANAEnterpriseID is the enterprise ID for IANA Information Elements
	IANAEnterpriseID uint32 = 0
	// Enterprise ID for reverse Information Elements
	ReverseEnterpriseID uint32 = 29305
)

var (
	// globalRegistryByID shows mapping EnterpriseID -> Info Element ID -> Info Element
	globalRegistryByID map[uint32]map[uint16]*entities.InfoElement
	// globalRegistryByName shows mapping EnterpriseID -> Info Element name -> Info Element
	globalRegistryByName map[uint32]map[string]*entities.InfoElement
)

func LoadRegistry() {
	globalRegistryByID = make(map[uint32]map[uint16]*entities.InfoElement)
	globalRegistryByID[AntreaEnterpriseID] = make(map[uint16]*entities.InfoElement)
	globalRegistryByID[IANAEnterpriseID] = make(map[uint16]*entities.InfoElement)
	globalRegistryByID[ReverseEnterpriseID] = make(map[uint16]*entities.InfoElement)

	globalRegistryByName = make(map[uint32]map[string]*entities.InfoElement)
	globalRegistryByName[AntreaEnterpriseID] = make(map[string]*entities.InfoElement)
	globalRegistryByName[IANAEnterpriseID] = make(map[string]*entities.InfoElement)
	globalRegistryByName[ReverseEnterpriseID] = make(map[string]*entities.InfoElement)

	loadIANARegistry()
	loadAntreaRegistry()
}

func GetInfoElementFromID(elementID uint16, enterpriseID uint32) (*entities.InfoElement, error) {
	if _, exist := globalRegistryByID[enterpriseID]; !exist {
		return nil, fmt.Errorf("Registry with EnterpriseID %d is not supported.", enterpriseID)
	}
	if element, exist := globalRegistryByID[enterpriseID][elementID]; !exist {
		return element, fmt.Errorf("Information Element with elementID %d in registry with enterpriseID %d cannot be found.", elementID, enterpriseID)
	} else {
		return element, nil
	}
}

func GetInfoElement(name string, enterpriseID uint32) (*entities.InfoElement, error) {
	if _, exist := globalRegistryByName[enterpriseID]; !exist {
		return nil, fmt.Errorf("Registry with EnterpriseID %d is not supported.", enterpriseID)
	}
	if element, exist := globalRegistryByName[enterpriseID][name]; !exist {
		return element, fmt.Errorf("Information Element with name %s in registry with enterpriseID %d cannot be found.", name, enterpriseID)
	} else {
		return element, nil
	}
}

func registerInfoElement(ie entities.InfoElement, enterpriseID uint32) error {
	if _, exist := globalRegistryByName[enterpriseID]; !exist {
		return fmt.Errorf("Registry with EnterpriseID %d is not supported.", ie.EnterpriseId)
	} else if _, exist = globalRegistryByName[enterpriseID][ie.Name]; exist {
		fmt.Errorf("Information element %s in registry with EnterpriseID %d has already been registered", ie.Name, ie.EnterpriseId)
	}
	globalRegistryByID[ie.EnterpriseId][ie.ElementId] = &ie
	globalRegistryByName[ie.EnterpriseId][ie.Name] = &ie

	if ie.EnterpriseId == IANAEnterpriseID { // handle reverse information element for IANA registry
		reverseIE, err := getIANAReverseInfoElement(ie.Name)
		if err == nil { // the information element has reverse information element
			globalRegistryByID[ReverseEnterpriseID][reverseIE.ElementId] = reverseIE
			globalRegistryByName[ReverseEnterpriseID][reverseIE.Name] = reverseIE
		}
	}
	return nil
}

func getIANAReverseInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie *entities.InfoElement
	if ie, exist = globalRegistryByName[IANAEnterpriseID][name]; !exist {
		err := fmt.Errorf("IANA Registry: There is no information element with name %s", name)
		return ie, err
	}
	if !isReversible(ie.Name) {
		err := fmt.Errorf("IANA Registry: The information element %s is not reverse element", name)
		return ie, err
	}
	reverseName := "reverse_" + strings.Title(ie.Name)
	return entities.NewInfoElement(reverseName, ie.ElementId, ie.DataType, ReverseEnterpriseID, ie.Len), nil
}

// Non-reversible Information Elements follow Section 6.1 of RFC5103
var nonReversibleIEs = map[string]bool{
	"biflowDirection":              true,
	"collectorIPv4Address":         true,
	"collectorIPv6Address":         true,
	"collectorTransportPort":       true,
	"commonPropertiesId":           true,
	"exportedMessageTotalCount":    true,
	"exportedOctetTotalCount":      true,
	"exportedFlowRecordTotalCount": true,
	"exporterIPv4Address":          true,
	"exporterIPv6Address":          true,
	"exporterTransportPort":        true,
	"exportInterface":              true,
	"exportProtocolVersion":        true,
	"exportTransportProtocol":      true,
	"flowId":                       true,
	"flowKeyIndicator":             true,
	"ignoredPacketTotalCount":      true,
	"ignoredOctetTotalCount":       true,
	"notSentFlowTotalCount":        true,
	"notSentPacketTotalCount":      true,
	"notSentOctetTotalCount":       true,
	"observationDomainId":          true,
	"observedFlowTotalCount":       true,
	"paddingOctets":                true,
	"templateId":                   true,
}

func isReversible(name string) bool {
	return !nonReversibleIEs[name]
}
