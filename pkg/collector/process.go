package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"io"
	"k8s.io/klog"
	"net"
	"sync"
	"time"
)

type collectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*TemplateField
	// templatesLock allows multiple readers or one writer at the same time
	templatesLock *sync.RWMutex
	// template lifetime
	templateTTL uint32
	// registries for decoding Information Element
	ianaRegistry   registry.Registry
	antreaRegistry registry.Registry
	// server information
	address net.Addr
}

type UDPCollectingProcess struct {
	collectingProcess
	// list of udp workers to process message
	workerList []*Worker
	// udp worker pool to receive and process message
	workerPool chan chan *bytes.Buffer
	// template lifetime channel
	templateLtCh chan struct{}
}

type TCPCollectingProcess struct {
	collectingProcess
}

// data struct of processed message
type Packet struct {
	Version      uint16
	BufferLength uint16
	SeqNumber    uint32
	ObsDomainID  uint32
	ExportTime   uint32
	FlowSets     interface{}
}

// Shared header fields for TemplateFlowSet and DataFlowSet
type FlowSetHeader struct {
	// 2 for templateFlowSet
	// 256-65535 for dataFlowSet (templateID)
	ID     uint16
	Length uint16
}

type TemplateFlowSet struct {
	FlowSetHeader
	Records []*TemplateField
}

type DataFlowSet struct {
	FlowSetHeader
	Records []*DataField
}

type TemplateField struct {
	ElementID     uint16
	ElementLength uint16
	EnterpriseID  uint32
}

type DataField struct {
	DataType entities.IEDataType
	Value    bytes.Buffer
}

func InitTCPCollectingProcess(address net.Addr, maxBufferSize uint16) (*TCPCollectingProcess, error) {
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	collectProc := &TCPCollectingProcess{
		collectingProcess{
			templatesMap:   make(map[uint32]map[uint16][]*TemplateField),
			templatesLock:  &sync.RWMutex{},
			templateTTL:    0,
			ianaRegistry:   ianaReg,
			antreaRegistry: antreaReg,
			address:        address,
		},
	}
	collectProc.start(address, maxBufferSize)
	return collectProc, nil
}

func InitUDPCollectingProcess(address net.Addr, maxBufferSize uint16, workerNum int, templateTTL uint32) (*UDPCollectingProcess, error) {
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	workerList := make([]*Worker, workerNum)
	workerPool := make(chan chan *bytes.Buffer)
	collectProc := &UDPCollectingProcess{
		collectingProcess: collectingProcess{
			templatesMap:   make(map[uint32]map[uint16][]*TemplateField),
			templatesLock:  &sync.RWMutex{},
			templateTTL:    templateTTL,
			ianaRegistry:   ianaReg,
			antreaRegistry: antreaReg,
			address:        address,
		},
		workerList: workerList,
		workerPool: workerPool,
	}

	collectProc.start(address, maxBufferSize, workerNum)
	return collectProc, nil
}

func (cp *collectingProcess) DecodeMessage(msgBuffer *bytes.Buffer) (*Packet, error) {
	packet := Packet{}
	flowSetHeader := FlowSetHeader{}
	err := decode(msgBuffer, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &flowSetHeader)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	if packet.Version != uint16(10) {
		return nil, fmt.Errorf("Collector only supports IPFIX (v10). Invalid version %d received.", packet.Version)
	}
	if flowSetHeader.ID == 2 {
		templateFlowSet := TemplateFlowSet{}
		records, err := cp.decodeTemplateRecord(msgBuffer, packet.ObsDomainID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		templateFlowSet.Records = records
		templateFlowSet.FlowSetHeader = flowSetHeader
		packet.FlowSets = templateFlowSet
	} else {
		dataFlowSet := DataFlowSet{}
		records, err := cp.decodeDataRecord(msgBuffer, packet.ObsDomainID, flowSetHeader.ID)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		dataFlowSet.Records = records
		dataFlowSet.FlowSetHeader = flowSetHeader
		packet.FlowSets = dataFlowSet
	}
	return &packet, nil
}

func (cp *collectingProcess) decodeTemplateRecord(templateBuffer *bytes.Buffer, obsDomainID uint32) ([]*TemplateField, error) {
	var templateID uint16
	var fieldCount uint16
	err := decode(templateBuffer, &templateID, &fieldCount)
	if err != nil {
		return nil, fmt.Errorf("Error in decoding message: %v", err)
	}
	fields := make([]*TemplateField, 0)
	for i := 0; i < int(fieldCount); i++ {
		field := TemplateField{}
		// check whether enterprise ID is 0 or not
		elementID := make([]byte, 2)
		err = decode(templateBuffer, &elementID, &field.ElementLength)
		if err != nil {
			return nil, fmt.Errorf("Error in decoding message: %v", err)
		}
		indicator := elementID[0] >> 7
		if indicator != 1 {
			field.EnterpriseID = uint32(0)
		} else {
			err = decode(templateBuffer, &field.EnterpriseID)
			if err != nil {
				return nil, fmt.Errorf("Error in decoding message: %v", err)
			}
			elementID[0] = elementID[0] ^ 0x80
		}
		field.ElementID = binary.BigEndian.Uint16(elementID)
		fields = append(fields, &field)
	}
	cp.addTemplate(obsDomainID, templateID, fields)
	return fields, nil
}

func (cp *collectingProcess) decodeDataRecord(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) ([]*DataField, error) {
	template, err := cp.getTemplate(obsDomainID, templateID)
	if err != nil {
		return nil, fmt.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
	fields := make([]*DataField, 0)
	for _, templateField := range template {
		length := int(templateField.ElementLength)
		field := DataField{}
		field.Value = bytes.Buffer{}
		field.Value.Write(dataBuffer.Next(length))
		field.DataType = cp.getDataType(templateField)
		fields = append(fields, &field)
	}
	return fields, nil
}

func (cp *collectingProcess) addTemplate(obsDomainID uint32, templateID uint16, fields []*TemplateField) {
	cp.templatesLock.Lock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*TemplateField)
	}
	cp.templatesMap[obsDomainID][templateID] = fields
	cp.templatesLock.Unlock()
	// template lifetime management
	if cp.address.Network() == "tcp" {
		return
	}
	if cp.templateTTL == 0 {
		cp.templateTTL = 1800 * 3 // Default value is 5400s
	}
	go func() {
		ticker := time.NewTicker(time.Duration(cp.templateTTL) * time.Second)
		defer ticker.Stop()
		select {
		case <-ticker.C:
			klog.Infof("Template with id %d, and obsDomainID %d is expired.", templateID, obsDomainID)
			cp.deleteTemplate(obsDomainID, templateID)
			break
		}
	}()
}

func (cp *collectingProcess) getTemplate(obsDomainID uint32, templateID uint16) ([]*TemplateField, error) {
	cp.templatesLock.RLock()
	if fields, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		cp.templatesLock.RUnlock()
		return fields, nil
	} else {
		cp.templatesLock.RUnlock()
		return fields, fmt.Errorf("Template %d with obsDomainID %d does not exist.", templateID, obsDomainID)
	}
}

func (cp *collectingProcess) deleteTemplate(obsDomainID uint32, templateID uint16) {
	cp.templatesLock.Lock()
	delete(cp.templatesMap[obsDomainID], templateID)
	cp.templatesLock.Unlock()
}

func (cp *collectingProcess) getDataType(templateField *TemplateField) entities.IEDataType {
	var registry registry.Registry
	if templateField.EnterpriseID == 0 { // IANA Registry
		registry = cp.ianaRegistry
	} else if templateField.EnterpriseID == 55829 { // Antrea Registry
		registry = cp.antreaRegistry
	}
	fieldName, err := registry.GetIENameFromID(templateField.ElementID)
	if err != nil {
		klog.Errorf("Information Element with id %d cannot be found.", templateField.ElementID)
	}
	ie, _ := registry.GetInfoElement(fieldName)
	return ie.DataType
}

func decode(buffer io.Reader, output ...interface{}) error {
	var err error
	for _, out := range output {
		err = binary.Read(buffer, binary.BigEndian, out)
	}
	return err
}
