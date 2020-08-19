package collector

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/vmware/go-ipfix/pkg/registry"
	"net"
	"sync"
	"testing"
	"time"
)

type Address struct {
	network string
	port    string
}

func (addr Address) Network() string {
	return addr.network
}

func (addr Address) String() string {
	return "0.0.0.0:" + addr.port
}

func TestTCPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address := Address{"tcp", "4730"}
	cp, err := InitTCPCollectingProcess(address, 1024)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		templateRecord := []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
		conn.Write(templateRecord)
		cp.stopChan <- true
	}()
	cp.Start()
	time.Sleep(5 * time.Second)
	assert.NotNil(t, cp.templatesMap[1], "TCP Collecting Process should receive and store the received template.")
}

func TestUDPCollectingProcess_ReceiveTemplateRecord(t *testing.T) {
	address := Address{"udp", "4731"}
	cp, err := InitUDPCollectingProcess(address, 1024, 2, 0)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		templateRecord := []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
		conn.Write(templateRecord)
		cp.stopChan <- true
	}()
	cp.Start()
	time.Sleep(2 * time.Second)
	assert.NotNil(t, cp.templatesMap[1], "UDP Collecting Process should receive and store the received template.")
}

func TestTCPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address := Address{"tcp", "4732"}
	cp, err := InitTCPCollectingProcess(address, 1024)
	// Add the templates before sending data record
	templateFields := []*TemplateField{
		{8, 4, 0},
		{12, 4, 0},
		{105, 65535, 55829},
	}
	cp.addTemplate(uint32(1), uint16(256), templateFields)
	if err != nil {
		t.Fatalf("TCP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(time.Second)
		conn, err := net.Dial(address.Network(), address.String())
		if err != nil {
			t.Fatalf("Cannot establish connection to %s", address.String())
		}
		defer conn.Close()
		dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 89, 105, 111, 117}
		conn.Write(dataRecord)
		cp.stopChan <- true
	}()
	cp.Start()
	time.Sleep(time.Second)
	assert.Equal(t, 1, len(cp.packets), "TCP Collecting Process should receive and store the received data record.")
}

func TestUDPCollectingProcess_ReceiveDataRecord(t *testing.T) {
	address := Address{"udp", "4733"}
	cp, err := InitUDPCollectingProcess(address, 1024, 2, 0)
	// Add the templates before sending data record
	templateFields := []*TemplateField{
		{8, 4, 0},
		{12, 4, 0},
		{105, 65535, 55829},
	}
	cp.addTemplate(uint32(1), uint16(256), templateFields)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 89, 105, 111, 117}
		conn.Write(dataRecord)
		cp.stopChan <- true
	}()
	cp.Start()
	time.Sleep(time.Second)
	assert.Equal(t, 1, len(cp.packets), "UDP Collecting Process should receive and store the received data record.")
}

func TestCollectingProcess_DecodeTemplateRecord(t *testing.T) {
	templateRecord := []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
	cp := collectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*TemplateField)
	cp.templatesLock = &sync.RWMutex{}
	cp.address = Address{"tcp", "4734"}
	packet, err := cp.DecodeMessage(bytes.NewBuffer(templateRecord))
	if err != nil {
		t.Fatalf("Got error in decoding template record: %v", err)
	}
	assert.Equal(t, uint16(10), packet.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), packet.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, packet.FlowSets, "Template record should be stored in packet flowset")
	assert.NotNil(t, cp.templatesMap[packet.ObsDomainID], "Template should be stored in template map")
	// Invalid version
	templateRecord = []byte{0, 9, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
	packet, err = cp.DecodeMessage(bytes.NewBuffer(templateRecord))
	assert.NotNil(t, err, "Error should be logged for invalid version")
	// Malformed record
	templateRecord = []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0}
	cp.templatesMap = make(map[uint32]map[uint16][]*TemplateField)
	packet, err = cp.DecodeMessage(bytes.NewBuffer(templateRecord))
	assert.NotNil(t, err, "Error should be logged for malformed template record")
	if _, exist := cp.templatesMap[uint32(1)]; exist {
		t.Fatal("Template should not be stored for malformed template record")
	}
}

func TestCollectingProcess_DecodeDataRecord(t *testing.T) {
	dataRecord := []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 17, 1, 2, 3, 4, 5, 6, 7, 8, 4, 89, 105, 111, 117}
	cp := collectingProcess{}
	cp.templatesMap = make(map[uint32]map[uint16][]*TemplateField)
	cp.templatesLock = &sync.RWMutex{}
	cp.address = Address{"tcp", "4735"}
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	cp.ianaRegistry = ianaReg
	cp.antreaRegistry = ianaReg
	// Decode without template
	_, err := cp.DecodeMessage(bytes.NewBuffer(dataRecord))
	assert.NotNil(t, err, "Error should be logged if corresponding template does not exist.")
	// Decode with template
	templateFields := []*TemplateField{
		{8, 4, 0},
		{12, 4, 0},
		{105, 65535, 55829},
	}
	cp.addTemplate(uint32(1), uint16(256), templateFields)
	packet, err := cp.DecodeMessage(bytes.NewBuffer(dataRecord))
	assert.Nil(t, err, "Error should not be logged if corresponding template exists.")
	assert.Equal(t, uint16(10), packet.Version, "Flow record version should be 10.")
	assert.Equal(t, uint32(1), packet.ObsDomainID, "Flow record obsDomainID should be 1.")
	assert.NotNil(t, packet.FlowSets, "Data record should be stored in packet flowset")
	// Malformed data record
	dataRecord = []byte{0, 10, 0, 33, 95, 40, 212, 159, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0}
	_, err = cp.DecodeMessage(bytes.NewBuffer(dataRecord))
	assert.NotNil(t, err, "Error should be logged for malformed data record")
}

func TestUDPCollectingProcess_TemplateExpire(t *testing.T) {
	address := Address{"udp", "4736"}
	cp, err := InitUDPCollectingProcess(address, 1024, 2, 5)
	if err != nil {
		t.Fatalf("UDP Collecting Process does not start correctly: %v", err)
	}
	go func() {
		time.Sleep(2 * time.Second)
		resolveAddr, err := net.ResolveUDPAddr(address.Network(), address.String())
		if err != nil {
			t.Errorf("UDP Address cannot be resolved.")
		}
		conn, err := net.DialUDP("udp", nil, resolveAddr)
		if err != nil {
			t.Errorf("UDP Collecting Process does not start correctly.")
		}
		defer conn.Close()
		templateRecord := []byte{0, 10, 0, 40, 95, 40, 211, 236, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 24, 1, 0, 0, 3, 0, 8, 0, 4, 0, 12, 0, 4, 128, 105, 255, 255, 0, 0, 218, 21}
		_, err = conn.Write(templateRecord)
		if err != nil {
			t.Errorf("Error in sending data to collector: %v", err)
		}
		cp.stopChan <- true
	}()
	cp.Start()
	assert.NotNil(t, cp.templatesMap[1][256], "Template should be stored in the template map.")
	time.Sleep(10 * time.Second)
	assert.Nil(t, cp.templatesMap[1][256], "Template should be deleted after 5 seconds.")
}