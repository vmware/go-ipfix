package intermediate

import (
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
	// workerPool is for storing worker channels to process message
	workerPool chan chan *entities.Message
	// messageChan is the channel to receive message
	messageChan chan *entities.Message
	// workerNum is the number of workers to process message
	workerNum int
	// workerList is the list of workers
	workerList []*worker
}

type Tuple struct {
	SourceAddress      [16]byte
	DestinationAddress [16]byte
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
	for _, record := range records {
		tuple, err := getTupleFromRecord(record)
		if err != nil {
			return err
		}
		a.correlateRecords(tuple, record)
	}
	return nil
}

func (a *aggregation) GetTupleRecordMap() map[Tuple][]entities.Record {
	a.tupleRecordLock.RLock()
	defer a.tupleRecordLock.RUnlock()
	return a.tupleRecordMap
}

// correlateRecords fills records info by correlating incoming and current records
func (a *aggregation) correlateRecords(tuple Tuple, record entities.Record) {
	srcFieldsToFill := []string{
		"destinationPodName",
		"destinationPodNamespace",
		"destinationNodeName",
	}
	existingRecords := a.GetTupleRecordMap()[tuple]
	// only fill the information for record from source node
	if isRecordFromSrc(record) {
		var isFilled bool
		for _, existingRec := range existingRecords {
			for _, field := range srcFieldsToFill {
				if record.ContainsInfoElement(field) {
					record.GetInfoElement(field).Value = existingRec.GetInfoElement(field).Value
					isFilled = true
				}
			}
			if isFilled {
				break
			}
		}
	} else {
		for _, existingRec := range existingRecords {
			if isRecordFromSrc(existingRec) {
				for _, field := range srcFieldsToFill {
					if record.ContainsInfoElement(field) {
						existingRec.GetInfoElement(field).Value = record.GetInfoElement(field).Value
					}
				}
			}
		}
	}
	a.addRecordToMap(tuple, record)
	a.removeDuplicates(tuple)
}

func (a *aggregation) removeDuplicates(tuple Tuple) {
	a.tupleRecordLock.Lock()
	defer a.tupleRecordLock.Unlock()
	records := a.tupleRecordMap[tuple]
	srcRecords := make([]entities.Record, 0)
	dstRecords := make([]entities.Record, 0)
	for _, record := range records {
		if isRecordFromSrc(record) {
			srcRecords = append(srcRecords, record)
		} else {
			dstRecords = append(dstRecords, record)
		}
	}
	if len(srcRecords) != 0 {
		a.tupleRecordMap[tuple] = srcRecords
	} else {
		a.tupleRecordMap[tuple] = dstRecords
	}
}

func (a *aggregation) addRecordToMap(tuple Tuple, record entities.Record) {
	a.tupleRecordLock.Lock()
	defer a.tupleRecordLock.Unlock()
	if _, exist := a.tupleRecordMap[tuple]; !exist {
		a.tupleRecordMap[tuple] = make([]entities.Record, 0)
	}
	a.tupleRecordMap[tuple] = append(a.tupleRecordMap[tuple], record)
}

func isRecordFromSrc(record entities.Record) bool {
	element := record.GetInfoElement("sourcePodName")
	if element != nil && element.Value != "" {
		return true
	}
	return false
}

// getTupleFromRecord returns 5-tuple from data record
func getTupleFromRecord(record entities.Record) (Tuple, error) {
	var srcIP, dstIP [16]byte
	var srcPort, dstPort uint16
	var proto uint8
	// record has complete 5-tuple information (IPv4)
	if record.ContainsInfoElement("sourceIPv4Address") && record.ContainsInfoElement("destinationIPv4Address") && record.ContainsInfoElement("sourceTransportPort") && record.ContainsInfoElement("destinationTransportPort") && record.ContainsInfoElement("protocolIdentifier") {
		srcIPAddr, ok := record.GetInfoElement("sourceIPv4Address").Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceIPv4Address is not in correct format.")
		}
		srcIP16Byte := net.IPv4(srcIPAddr[0], srcIPAddr[1], srcIPAddr[2], srcIPAddr[3])
		copy(srcIP[:], srcIP16Byte)
		dstIPAddr, ok := record.GetInfoElement("destinationIPv4Address").Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationIPv4Address is not in correct format.")
		}
		dstIP16Byte := net.IPv4(dstIPAddr[0], dstIPAddr[1], dstIPAddr[2], dstIPAddr[3])
		copy(dstIP[:], dstIP16Byte)
		srcPortNum, ok := record.GetInfoElement("sourceTransportPort").Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceTransportPort is not in correct format.")
		}
		srcPort = srcPortNum
		dstPortNum, ok := record.GetInfoElement("destinationTransportPort").Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationTransportPort is not in correct format.")
		}
		dstPort = dstPortNum
		protoNum, ok := record.GetInfoElement("protocolIdentifier").Value.(uint8)
		if !ok {
			return Tuple{}, fmt.Errorf("protocolIdentifier is not in correct format.")
		}
		proto = protoNum
	} else if record.ContainsInfoElement("sourceIPv6Address") && record.ContainsInfoElement("destinationIPv6Address") && record.ContainsInfoElement("sourceTransportPort") && record.ContainsInfoElement("destinationTransportPort") && record.ContainsInfoElement("protocolIdentifier") {
		srcIPAddr, ok := record.GetInfoElement("sourceIPv6Address").Value.([]byte)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceIPv4Address is not in correct format.")
		}
		copy(srcIP[:], srcIPAddr[:])
		dstIPAddr, ok := record.GetInfoElement("destinationIPv6Address").Value.([]byte)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationIPv4Address is not in correct format.")
		}
		copy(dstIP[:], dstIPAddr[:])
		srcPortNum, ok := record.GetInfoElement("sourceTransportPort").Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceTransportPort is not in correct format.")
		}
		srcPort = srcPortNum
		dstPortNum, ok := record.GetInfoElement("destinationTransportPort").Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationTransportPort is not in correct format.")
		}
		dstPort = dstPortNum
		protoNum, ok := record.GetInfoElement("protocolIdentifier").Value.(uint8)
		if !ok {
			return Tuple{}, fmt.Errorf("protocolIdentifier is not in correct format.")
		}
		proto = protoNum
	} else {
		return Tuple{}, fmt.Errorf("missing 5-tuple value(s) in the record.")
	}
	// TODO: support 5-tuple IPv6
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
