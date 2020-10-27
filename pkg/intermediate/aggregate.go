package intermediate

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type aggregation struct {
	// tupleRecordMap maps each connection with its records
	tupleRecordMap map[Tuple][]entities.Record
	// tupleRecordLock allows multiple readers or one writer at the same time
	tupleRecordLock sync.RWMutex
	// workerPool is for exchanging worker channels to process message
	workerPool chan chan *entities.Message
	// messageChan is the channel to receive message
	messageChan chan *entities.Message
	// workerNum is the number of workers to process message
	workerNum int
	// workerList is the list of workers
	workerList []*worker
}

type Tuple struct {
	// SourceAddress is the encoded format of sourceIPv4Address
	SourceAddress uint32
	// DestinationAddress is the encoded format of destinationIPv4Address
	DestinationAddress uint32
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

func InitAggregationProcess(messageChan chan *entities.Message, workerNum int) (*aggregation, error) {
	if messageChan == nil {
		return nil, fmt.Errorf("Cannot create aggregation process without message channel.")
	} else if workerNum <= 0 {
		return nil, fmt.Errorf("Worker number cannot be <= 0.")
	}
	return &aggregation{
		make(map[Tuple][]entities.Record),
		sync.RWMutex{},
		make(chan chan *entities.Message),
		messageChan,
		workerNum,
		make([]*worker, 0),
	}, nil
}

func (a *aggregation) Start() {
	for i := 0; i < a.workerNum; i++ {
		w := createWorker(i, a.workerPool, a.AggregateMsgBy5Tuple)
		w.start()
		a.workerList = append(a.workerList, w)
	}
	for message := range a.messageChan {
		channel := <-a.workerPool
		channel <- message
	}
}

func (a *aggregation) Stop() {
	for _, worker := range a.workerList {
		worker.stop()
	}
}

// AggregateMsgBy5Tuple gets 5-tuple info from records in message and stores in cache
func (a *aggregation) AggregateMsgBy5Tuple(message *entities.Message) error {
	addOriginalExporterInfo(message)
	if message.Set.GetSetType() == entities.Template { // skip template records
		return nil
	}
	records := message.Set.GetRecords()
	a.tupleRecordLock.Lock()
	defer a.tupleRecordLock.Unlock()
	for _, record := range records {
		tuple, err := getTupleFromRecord(record)
		if err != nil {
			return err
		}
		if _, exist := a.tupleRecordMap[tuple]; !exist {
			a.tupleRecordMap[tuple] = make([]entities.Record, 0)
		}
		a.tupleRecordMap[tuple] = append(a.tupleRecordMap[tuple], record)
	}
	return nil
}

func (a *aggregation) GetTupleRecordMap() map[Tuple][]entities.Record {
	a.tupleRecordLock.RLock()
	defer a.tupleRecordLock.RUnlock()
	return a.tupleRecordMap
}

// getTupleFromRecord returns 5-tuple from data record
func getTupleFromRecord(record entities.Record) (Tuple, error) {
	var srcIP, dstIP uint32
	var srcPort, dstPort uint16
	var proto uint8
	// count is for checking whether 5-tuple is fully collected
	count := 0
	for _, infoElementWithValue := range record.GetInfoElements() {
		if infoElementWithValue.Element.Name == "sourceIPv4Address" {
			addr, ok := infoElementWithValue.Value.([]byte)
			if !ok {
				return Tuple{}, fmt.Errorf("sourceIPv4Address is not in correct format.")
			}
			srcIP = binary.BigEndian.Uint32(addr)
			count++
		} else if infoElementWithValue.Element.Name == "destinationIPv4Address" {
			addr, ok := infoElementWithValue.Value.([]byte)
			if !ok {
				return Tuple{}, fmt.Errorf("destinationIPv4Address is not in correct format.")
			}
			dstIP = binary.BigEndian.Uint32(addr)
			count++
		} else if infoElementWithValue.Element.Name == "sourceTransportPort" {
			v, ok := infoElementWithValue.Value.(uint16)
			if !ok {
				return Tuple{}, fmt.Errorf("sourceTransportPort is not in correct format.")
			}
			srcPort = v
			count++
		} else if infoElementWithValue.Element.Name == "destinationTransportPort" {
			v, ok := infoElementWithValue.Value.(uint16)
			if !ok {
				return Tuple{}, fmt.Errorf("destinationTransportPort is not in correct format.")
			}
			dstPort = v
			count++
		} else if infoElementWithValue.Element.Name == "protocolIdentifier" {
			v, ok := infoElementWithValue.Value.(uint8)
			if !ok {
				return Tuple{}, fmt.Errorf("protocolIdentifier is not in correct format.")
			}
			proto = v
			count++
		}
	}
	if count != 5 {
		return Tuple{}, fmt.Errorf("Missing 5-tuple value(s) in the record.")
	}
	return Tuple{srcIP, dstIP, proto, srcPort, dstPort}, nil
}

// addOriginalExporterInfo adds originalExporterIPv4Address and originalObservationDomainId to records in message set
func addOriginalExporterInfo(message *entities.Message) error {
	set := message.Set
	records := set.GetRecords()
	for _, record := range records {
		var originalExporterIPv4Address, originalObservationDomainId *entities.InfoElementWithValue

		// Add originalExporterIPv4Address
		ie, err := registry.GetInfoElement("originalExporterIPv4Address", registry.IANAEnterpriseID)
		if err != nil {
			return fmt.Errorf("IANA Registry is not loaded correctly with originalExporterIPv4Address.")
		}
		if set.GetSetType() == entities.Template {
			originalExporterIPv4Address = entities.NewInfoElementWithValue(ie, nil)
		} else if set.GetSetType() == entities.Data {
			originalExporterIPv4Address = entities.NewInfoElementWithValue(ie, net.ParseIP(message.ExportAddress))
		} else {
			return fmt.Errorf("Set type %d is not supported.", set.GetSetType())
		}
		_, err = record.AddInfoElement(originalExporterIPv4Address, false)
		if err != nil {
			return err
		}

		// Add originalObservationDomainId
		ie, err = registry.GetInfoElement("originalObservationDomainId", registry.IANAEnterpriseID)
		if err != nil {
			return fmt.Errorf("IANA Registry is not loaded correctly with originalObservationDomainId.")
		}
		if set.GetSetType() == entities.Template {
			originalObservationDomainId = entities.NewInfoElementWithValue(ie, nil)
		} else if set.GetSetType() == entities.Data {
			originalObservationDomainId = entities.NewInfoElementWithValue(ie, message.ObsDomainID)
		} else {
			return fmt.Errorf("Set type %d is not supported.", set.GetSetType())
		}
		_, err = record.AddInfoElement(originalObservationDomainId, false)
		if err != nil {
			return err
		}
	}
	return nil
}
