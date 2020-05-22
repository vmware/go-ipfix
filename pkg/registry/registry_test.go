package registry

import (
	"github.com/srikartati/go-ipfixlib/pkg/entities"
	"github.com/stretchr/testify/assert"
	"testing"
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
	assert.Equal(t, ie, entities.InfoElement{}, "IANA registry GetInfoElement did not return correct value.")
	assert.NotEqual(t, error, nil, "IANA registry GetInfoElement should return error if cannot find InfoElement.")
	reg.registerInfoElement(entities.InfoElement{"ingressInterface", 104, 13, 55829, 65535})
	ie, error = reg.GetInfoElement("ingressInterface")
	assert.Equal(t, ie.Name, "ingressInterface", "IANA registry GetInfoElement did not return correct value.")
	assert.Equal(t, error, nil, "IANA registry GetInfoElement should not return error if InfoElement exists.")
}

func TestIanaRegistryLoadRegistry(t *testing.T) {
	reg := NewIanaRegistry()
	reg.LoadRegistry()
	ie, error := reg.GetInfoElement("ipNextHopIPv6Address")
	errorMsg := "IANA registry LoadRegistry did not load registry correctly."
	assert.Equal(t, ie.Name, "ipNextHopIPv6Address", errorMsg)
	assert.Equal(t, error, nil, errorMsg)
	ie, error = reg.GetInfoElement("sourcePodName")
	assert.Equal(t, ie, entities.InfoElement{}, errorMsg)
	assert.NotEqual(t, error, nil, errorMsg)
}

func TestAntreaRegistryGetInfoElement(t *testing.T) {
	reg := NewAntreaRegistry()
	ie, error := reg.GetInfoElement("sourceNodeName")
	assert.Equal(t, ie, entities.InfoElement{}, "Antrea registry GetInfoElement did not return correct value.")
	assert.NotEqual(t, error, nil, "Antrea registry GetInfoElement should return error if cannot find InfoElement.")
	reg.registerInfoElement(entities.InfoElement{"sourceNodeName", 104, 13, 55829, 65535})
	ie, error = reg.GetInfoElement("sourceNodeName")
	assert.Equal(t, ie.Name, "sourceNodeName", "Antrea registry GetInfoElement did not return correct value.")
	assert.Equal(t, error, nil, "Antrea registry GetInfoElement should not return error if InfoElement exists.")
}

func TestAntreaRegistryLoadRegistry(t *testing.T) {
	reg := NewAntreaRegistry()
	reg.LoadRegistry()
	ie, error := reg.GetInfoElement("destinationClusterIP")
	errorMsg := "Antrea registry LoadRegistry did not load registry correctly."
	assert.Equal(t, ie.Name, "destinationClusterIP", errorMsg)
	assert.Equal(t, error, nil, errorMsg)
	ie, error = reg.GetInfoElement("sourceMacAddress")
	assert.Equal(t, ie, entities.InfoElement{}, errorMsg)
	assert.NotEqual(t, error, nil, errorMsg)
}