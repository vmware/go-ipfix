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
	// correlateFields are the fields to be filled in correlating process
	correlateFields []string
}

type Tuple struct {
	SourceAddress      string
	DestinationAddress string
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

func InitAggregationProcess(messageChan chan *entities.Message, workerNum int, correlateFields []string) (*aggregation, error) {
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
		correlateFields,
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

func (a *aggregation) DeleteTupleFromMap(tuple Tuple) {
	a.tupleRecordLock.Lock()
	defer a.tupleRecordLock.Unlock()
	delete(a.tupleRecordMap, tuple)
}

// correlateRecords fills records info by correlating incoming and current records
func (a *aggregation) correlateRecords(tuple Tuple, record entities.Record) {
	existingRecords := a.GetTupleRecordMap()[tuple]
	// only fill the information for record from source node
	if isRecordFromSrc(record) {
		var isFilled bool
		for _, existingRec := range existingRecords {
			for _, field := range a.correlateFields {
				if containsInfoElement(record.GetInfoElementMap(), field) {
					record.GetInfoElementMap()[field].Value = existingRec.GetInfoElementMap()[field].Value
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
				for _, field := range a.correlateFields {
					if containsInfoElement(record.GetInfoElementMap(), field) {
						existingRec.GetInfoElementMap()[field].Value = record.GetInfoElementMap()[field].Value
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
	element, exist := record.GetInfoElementMap()["sourcePodName"]
	if exist && element.Value != "" {
		return true
	}
	return false
}

// getTupleFromRecord returns 5-tuple from data record
func getTupleFromRecord(record entities.Record) (Tuple, error) {
	var srcIP, dstIP string
	var srcPort, dstPort uint16
	var proto uint8
	// record has complete 5-tuple information (IPv4)
	infoElementMap := record.GetInfoElementMap()
	if containsInfoElement(infoElementMap, "sourceIPv4Address") && containsInfoElement(infoElementMap, "destinationIPv4Address") && containsInfoElement(infoElementMap, "sourceTransportPort") && containsInfoElement(infoElementMap, "destinationTransportPort") && containsInfoElement(infoElementMap, "protocolIdentifier") {
		srcIPAddr, ok := infoElementMap["sourceIPv4Address"].Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceIPv4Address is not in correct format.")
		}
		srcIP = srcIPAddr.String()
		dstIPAddr, ok := infoElementMap["destinationIPv4Address"].Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationIPv4Address is not in correct format.")
		}
		dstIP = dstIPAddr.String()
		srcPortNum, ok := infoElementMap["sourceTransportPort"].Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceTransportPort is not in correct format.")
		}
		srcPort = srcPortNum
		dstPortNum, ok := infoElementMap["destinationTransportPort"].Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationTransportPort is not in correct format.")
		}
		dstPort = dstPortNum
		protoNum, ok := infoElementMap["protocolIdentifier"].Value.(uint8)
		if !ok {
			return Tuple{}, fmt.Errorf("protocolIdentifier is not in correct format.")
		}
		proto = protoNum
	} else if containsInfoElement(infoElementMap, "sourceIPv6Address") && containsInfoElement(infoElementMap, "destinationIPv6Address") && containsInfoElement(infoElementMap, "sourceTransportPort") && containsInfoElement(infoElementMap, "destinationTransportPort") && containsInfoElement(infoElementMap, "protocolIdentifier") {
		srcIPAddr, ok := infoElementMap["sourceIPv6Address"].Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceIPv6Address is not in correct format.")
		}
		srcIP = net.IP(srcIPAddr).String()
		dstIPAddr, ok := infoElementMap["destinationIPv6Address"].Value.(net.IP)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationIPv6Address is not in correct format.")
		}
		dstIP = net.IP(dstIPAddr).String()
		srcPortNum, ok := infoElementMap["sourceTransportPort"].Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("sourceTransportPort is not in correct format.")
		}
		srcPort = srcPortNum
		dstPortNum, ok := infoElementMap["destinationTransportPort"].Value.(uint16)
		if !ok {
			return Tuple{}, fmt.Errorf("destinationTransportPort is not in correct format.")
		}
		dstPort = dstPortNum
		protoNum, ok := infoElementMap["protocolIdentifier"].Value.(uint8)
		if !ok {
			return Tuple{}, fmt.Errorf("protocolIdentifier is not in correct format.")
		}
		proto = protoNum
	} else {
		return Tuple{}, fmt.Errorf("missing 5-tuple value(s) in the record.")
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

func containsInfoElement(recordMap map[string]*entities.InfoElementWithValue, name string) bool {
	if _, exist := recordMap[name]; exist {
		return true
	}
	return false
}
