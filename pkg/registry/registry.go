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

const reversePen = uint32(29305)

type Registry interface {
	LoadRegistry()
	GetInfoElement(name string) (*entities.InfoElement, error)
	GetReverseInfoElement(name string) (*entities.InfoElement, error)
}

type ianaRegistry struct {
	registry map[string]entities.InfoElement
}

type antreaRegistry struct {
	registry map[string]entities.InfoElement
}

var globalReg map[uint32]map[uint16]entities.InfoElement

func LoadRegistry() {
	globalReg = make(map[uint32]map[uint16]entities.InfoElement)
	antreaReg := NewAntreaRegistry()
	antreaReg.LoadRegistry()
	ianaReg := NewIanaRegistry()
	ianaReg.LoadRegistry()
}

func GetInfoElementFromID(elementID uint16, enterpriseID uint32) (entities.InfoElement, error) {
	if element, exist := globalReg[enterpriseID][elementID]; !exist {
		return element, fmt.Errorf("Information Element with elementID %d and enterpriseID %d cannot be found.", elementID, enterpriseID)
	} else {
		return element, nil
	}
}

func NewIanaRegistry() *ianaRegistry {
	reg := make(map[string]entities.InfoElement)
	globalReg[IANAEnterpriseID] = make(map[uint16]entities.InfoElement)
	return &ianaRegistry{
		registry: reg,
	}
}

func NewAntreaRegistry() *antreaRegistry {
	reg := make(map[string]entities.InfoElement)
	globalReg[AntreaEnterpriseID] = make(map[uint16]entities.InfoElement)
	return &antreaRegistry{
		registry: reg,
	}
}

func (reg *ianaRegistry) registerInfoElement(ie entities.InfoElement) error {
	if _, exist := reg.registry[ie.Name]; exist {
		return fmt.Errorf("IANA Registry: Information element %s has already been registered", ie.Name)
	}
	reg.registry[ie.Name] = ie
	globalReg[IANAEnterpriseID][ie.ElementId] = ie
	return nil
}

func (reg *ianaRegistry) GetInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = reg.registry[name]; !exist {
		err := fmt.Errorf("IANA Registry: There is no information element with name %s", name)
		return &ie, err
	}
	return &ie, nil
}

func (reg *ianaRegistry) GetReverseInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = reg.registry[name]; !exist {
		err := fmt.Errorf("IANA Registry: There is no information element with name %s", name)
		return &ie, err
	}
	if !isReversible(ie.Name) {
		err := fmt.Errorf("IANA Registry: The information element %s is not reverse element", name)
		return &ie, err
	}
	reverseName := "reverse_" + strings.Title(ie.Name)
	return entities.NewInfoElement(reverseName, ie.ElementId, ie.DataType, reversePen, ie.Len), nil
}

func (reg *antreaRegistry) registerInfoElement(ie entities.InfoElement) error {
	if _, exist := reg.registry[ie.Name]; exist {
		return fmt.Errorf("Antrea Registry: Information element %s has already been registered", ie.Name)
	}
	reg.registry[ie.Name] = ie
	globalReg[AntreaEnterpriseID][ie.ElementId] = ie
	return nil
}

func (reg *antreaRegistry) GetInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = reg.registry[name]; !exist {
		err := fmt.Errorf("Antrea Registry: There is no information element with name %s", name)
		return &ie, err
	}
	return &ie, nil
}

func (reg *antreaRegistry) GetReverseInfoElement(name string) (*entities.InfoElement, error) {
	var exist bool
	var ie entities.InfoElement
	if ie, exist = reg.registry[name]; !exist {
		err := fmt.Errorf("Antrea Registry: There is no information element with name %s", name)
		return &ie, err
	}
	reverseName := "reverse_" + strings.Title(ie.Name)
	return entities.NewInfoElement(reverseName, ie.ElementId, ie.DataType, reversePen, ie.Len), nil
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
