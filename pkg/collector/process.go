package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"k8s.io/klog"
	"net"
	"sync"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type CollectingProcess struct {
	// for each obsDomainID, there is a map of templates
	templatesMap map[uint32]map[uint16][]*TemplateField
	// templatesLock allows multiple readers or one writer at the same time
	templatesLock  *sync.RWMutex
	ianaRegistry   registry.Registry
	antreaRegistry registry.Registry
}

type Packet struct {
	Version      uint16
	BufferLength uint16
	SeqNumber    uint32
	ObsDomainID  uint32
	ExportTime   uint32
	FlowSets     interface{}
}

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

func InitCollectingProcess(address net.Addr, maxBufferSize uint16) (*CollectingProcess, error, ) {
	ianaReg := registry.NewIanaRegistry()
	antreaReg := registry.NewAntreaRegistry()
	ianaReg.LoadRegistry()
	antreaReg.LoadRegistry()
	collectProc := &CollectingProcess{
		templatesMap:   make(map[uint32]map[uint16][]*TemplateField),
		templatesLock:  &sync.RWMutex{},
		ianaRegistry:   ianaReg,
		antreaRegistry: antreaReg,
	}
	if address.Network() == "udp" {
		collectProc.startUDPServer(address, maxBufferSize)
	}
	return collectProc, nil
}

func (cp *CollectingProcess) startUDPServer(address net.Addr, maxBufferSize uint16) {
	listener, err := net.ResolveUDPAddr(address.Network(), address.String())
	conn, err := net.ListenUDP("udp", listener)
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", address.String(), err)
	}
	errChan := make(chan error, 1)

	defer conn.Close()
	klog.Info("Start collecting process")
	for {
		buff := make([]byte, maxBufferSize)
		size, err := conn.Read(buff)
		if err != nil {
			errChan <- err
		}
		payload := make([]byte, size)
		copy(payload, buff[0:size])
		klog.Infof("Receiving %d bytes from %s", size, address.String())
		cp.DecodeMessage(bytes.NewBuffer(payload))
	}
}

func (cp *CollectingProcess) DecodeMessage(msgBuffer *bytes.Buffer) *Packet {
	packet := Packet{}
	flowSetHeader := FlowSetHeader{}
	decode(msgBuffer, &packet.Version, &packet.BufferLength, &packet.ExportTime, &packet.SeqNumber, &packet.ObsDomainID, &flowSetHeader)
	if flowSetHeader.ID == 2 {
		templateFlowSet := TemplateFlowSet{}
		templateFlowSet.Records = cp.decodeTemplateRecord(msgBuffer, packet.ObsDomainID)
		templateFlowSet.FlowSetHeader = flowSetHeader
		packet.FlowSets = templateFlowSet
	} else {
		dataFlowSet := DataFlowSet{}
		dataFlowSet.Records = cp.decodeDataRecord(msgBuffer, packet.ObsDomainID, flowSetHeader.ID)
		dataFlowSet.FlowSetHeader = flowSetHeader
		packet.FlowSets = dataFlowSet
	}
	return &packet
}

func (cp *CollectingProcess) decodeTemplateRecord(templateBuffer *bytes.Buffer, obsDomainID uint32) []*TemplateField {
	var templateID uint16
	var fieldCount uint16
	decode(templateBuffer, &templateID, &fieldCount)
	fields := make([]*TemplateField, 0)
	for i := 0; i < int(fieldCount); i++ {
		field := TemplateField{}
		// check whether enterprise ID is 0 or not
		elementID := make([]byte, 2)
		decode(templateBuffer, &elementID, &field.ElementLength)
		indicator := elementID[0] >> 7
		if indicator != 1 {
			field.EnterpriseID = uint32(0)
		} else {
			decode(templateBuffer, &field.EnterpriseID)
			elementID[0] = elementID[0] ^ 0x80
		}
		field.ElementID = binary.BigEndian.Uint16(elementID)
		fields = append(fields, &field)
	}
	cp.AddTemplate(obsDomainID, templateID, fields)
	return fields
}

func (cp *CollectingProcess) decodeDataRecord(dataBuffer *bytes.Buffer, obsDomainID uint32, templateID uint16) []*DataField {
	template, err := cp.GetTemplate(obsDomainID, templateID)
	if err != nil {
		klog.Errorf("Template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	} else {
		fields := make([]*DataField, 0)
		for _, templateField := range template {
			length := int(templateField.ElementLength)
			field := DataField{}
			field.Value = bytes.Buffer{}
			field.Value.Write(dataBuffer.Next(length))
			field.DataType = cp.getDataType(templateField)
			fields = append(fields, &field)
		}
		return fields
	}
	return nil
}

func (cp *CollectingProcess) getDataType(templateField *TemplateField) entities.IEDataType {
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

func (cp *CollectingProcess) AddTemplate(obsDomainID uint32, templateID uint16, fields []*TemplateField) {
	cp.templatesLock.Lock()
	if _, exists := cp.templatesMap[obsDomainID]; !exists {
		cp.templatesMap[obsDomainID] = make(map[uint16][]*TemplateField)
	}
	cp.templatesMap[obsDomainID][templateID] = fields
	cp.templatesLock.Unlock()
}

func (cp *CollectingProcess) GetTemplate(obsDomainID uint32, templateID uint16) ([]*TemplateField, error) {
	cp.templatesLock.RLock()
	if fields, exists := cp.templatesMap[obsDomainID][templateID]; exists {
		cp.templatesLock.RUnlock()
		return fields, nil
	} else {
		cp.templatesLock.RUnlock()
		return fields, fmt.Errorf("Template %d with obsDomainID %d does not exist.", templateID, obsDomainID)
	}
}

func decode(buffer io.Reader, output ...interface{}) error {
	var err error
	for _, out := range output {
		err = binary.Read(buffer, binary.BigEndian, out)
	}
	return err
}
