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

//type ianaRegistry struct {
//	registry map[string]entities.InfoElement
//}
//
//type antreaRegistry struct {
//	registry map[string]entities.InfoElement
//}

var (
	// globalRegistry shows mapping EnterpriseID -> Info Element ID -> Info Element
	globalRegistry map[uint32]map[uint16]entities.InfoElement
	// ianaRegistry shows mapping Info Element name -> Info Element for IANA Registry
	ianaRegistry map[string]entities.InfoElement
	// antreaRegistry shows mapping Info Element name -> Info Element for Antrea Registry
	antreaRegistry map[string]entities.InfoElement
)

func LoadRegistry() {
	globalRegistry = make(map[uint32]map[uint16]entities.InfoElement)

	antreaRegistry = make(map[string]entities.InfoElement)
	globalRegistry[AntreaEnterpriseID] = make(map[uint16]entities.InfoElement)
	loadAntreaRegistry()

	ianaRegistry = make(map[string]entities.InfoElement)
	globalRegistry[IANAEnterpriseID] = make(map[uint16]entities.InfoElement)
	globalRegistry[ReverseEnterpriseID] = make(map[uint16]entities.InfoElement)
	loadIANARegistry()
}

func GetInfoElementFromID(elementID uint16, enterpriseID uint32) (entities.InfoElement, error) {
	if element, exist := globalRegistry[enterpriseID][elementID]; !exist {
		return element, fmt.Errorf("Information Element with elementID %d and enterpriseID %d cannot be found.", elementID, enterpriseID)
	} else {
		return element, nil
	}
}

func GetIANAInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = ianaRegistry[name]; !exist {
		err := fmt.Errorf("IANA Registry: There is no information element with name %s", name)
		return &ie, err
	}
	return &ie, nil
}

func GetIANAReverseIE(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = ianaRegistry[name]; !exist {
		err := fmt.Errorf("IANA Registry: There is no information element with name %s", name)
		return &ie, err
	}
	if !isReversible(ie.Name) {
		err := fmt.Errorf("IANA Registry: The information element %s is not reverse element", name)
		return &ie, err
	}
	reverseName := "reverse_" + strings.Title(ie.Name)
	return entities.NewInfoElement(reverseName, ie.ElementId, ie.DataType, ReverseEnterpriseID, ie.Len), nil
}

func GetAntreaInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = antreaRegistry[name]; !exist {
		err := fmt.Errorf("Antrea Registry: There is no information element with name %s", name)
		return &ie, err
	}
	return &ie, nil
}

func GetAntreaReverseIE(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = antreaRegistry[name]; !exist {
		err := fmt.Errorf("Antrea Registry: There is no information element with name %s", name)
		return &ie, err
	}
	if !isReversible(ie.Name) {
		err := fmt.Errorf("Antrea Registry: The information element %s is not reverse element", name)
		return &ie, err
	}
	reverseName := "reverse_" + strings.Title(ie.Name)
	return entities.NewInfoElement(reverseName, ie.ElementId, ie.DataType, ReverseEnterpriseID, ie.Len), nil
}

func registerIANAIE(ie entities.InfoElement) error {
	if _, exist := ianaRegistry[ie.Name]; exist {
		return fmt.Errorf("IANA Registry: Information element %s has already been registered", ie.Name)
	}
	ianaRegistry[ie.Name] = ie
	globalRegistry[IANAEnterpriseID][ie.ElementId] = ie
	reverseIE, err := GetIANAReverseIE(ie.Name)
	if err == nil { // the information element has reverse information element
		globalRegistry[ReverseEnterpriseID][ie.ElementId] = *reverseIE
	}
	return nil
}

func registerAntreaIE(ie entities.InfoElement) error {
	if _, exist := antreaRegistry[ie.Name]; exist {
		return fmt.Errorf("Antrea Registry: Information element %s has already been registered", ie.Name)
	}
	antreaRegistry[ie.Name] = ie
	globalRegistry[AntreaEnterpriseID][ie.ElementId] = ie
	return nil
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
