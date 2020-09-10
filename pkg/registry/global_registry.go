package registry

import (
	"fmt"

	"github.com/vmware/go-ipfix/pkg/entities"
)

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
