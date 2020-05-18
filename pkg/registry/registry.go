package registry

import (
	"fmt"

	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

var IANARegistry map[string]entities.InfoElement

func Init() {
	IANARegistry = make(map[string]entities.InfoElement)
	LoadIANARegistry()
}

func RegisterInfoElement(ie entities.InfoElement) error {
	if _, exist := IANARegistry[ie.Name]; exist {
		return fmt.Errorf("registry: Information element %s has already been registered", ie.Name)
	}
	IANARegistry[ie.Name] = ie
	return nil
}

func GetInfoElement(name string) (ie entities.InfoElement, err error) {
	var exist bool
	if ie, exist = IANARegistry[name]; !exist {
		err = fmt.Errorf("registry: There is no information element with name %s", name)
	}
	return
}