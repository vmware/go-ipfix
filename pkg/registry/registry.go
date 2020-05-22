package registry

import (
	"fmt"
	"github.com/srikartati/go-ipfixlib/pkg/entities"
)

type Registry interface {
	LoadRegistry()
	GetInfoElement(name string) (ie entities.InfoElement, err error)
}

type ianaRegistry struct {
	registry map[string]entities.InfoElement
}

type antreaRegistry struct {
	registry map[string]entities.InfoElement
}


func NewIanaRegistry() *ianaRegistry {
	reg := make(map[string]entities.InfoElement)
	return &ianaRegistry{
		registry: reg,
	}
}

func NewAntreaRegistry() *antreaRegistry {
	reg := make(map[string]entities.InfoElement)
	return &antreaRegistry{
		registry: reg,
	}
}

func (reg *ianaRegistry) registerInfoElement(ie entities.InfoElement) error {
	if _, exist := reg.registry[ie.Name]; exist {
		return fmt.Errorf("IANA Registry: Information element %s has already been registered", ie.Name)
	}
	reg.registry[ie.Name] = ie
	return nil
}

func (reg *ianaRegistry) GetInfoElement(name string) (ie entities.InfoElement, err error) {
	var exist bool
	if ie, exist = reg.registry[name]; !exist {
		err = fmt.Errorf("IANA Registry: There is no information element with name %s", name)
	}
	return
}

func (reg *antreaRegistry) registerInfoElement(ie entities.InfoElement) error {
	if _, exist := reg.registry[ie.Name]; exist {
		return fmt.Errorf("Antrea Registry: Information element %s has already been registered", ie.Name)
	}
	reg.registry[ie.Name] = ie
	return nil
}

func (reg *antreaRegistry) GetInfoElement(name string) (ie entities.InfoElement, err error) {
	var exist bool
	if ie, exist = reg.registry[name]; !exist {
		err = fmt.Errorf("Antrea Registry: There is no information element with name %s", name)
	}
	return
}