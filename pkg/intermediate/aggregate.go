package intermediate

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

type AggregationProcess struct {
	// flowKeyRecordMap maps each connection (5-tuple) with its records
	flowKeyRecordMap map[FlowKey][]entities.Record
	// mutex allows multiple readers or one writer at the same time
	mutex sync.RWMutex
	// messageChan is the channel to receive the message
	messageChan chan *entities.Message
	// workerNum is the number of workers to process the messages
	workerNum int
	// workerList is the list of workers
	workerList []*worker
	// correlateFields are the fields to be filled in correlating process
	correlateFields []string
	// stopChan is the channel to receive stop message
	stopChan chan bool
}

type FlowKey struct {
	SourceAddress      string
	DestinationAddress string
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
}

type AggregationInput struct {
	MessageChan     chan *entities.Message
	WorkerNum       int
	CorrelateFields []string
}

type FlowKeyRecordMapCallBack func(key FlowKey, records []entities.Record) error

// InitAggregationProcess takes in message channel (e.g. from collector) as input channel, workerNum(number of workers to process message)
// and correlateFields (fields to be correlated and filled).
func InitAggregationProcess(input AggregationInput) (*AggregationProcess, error) {
	if input.MessageChan == nil {
		return nil, fmt.Errorf("cannot create AggregationProcess process without message channel")
	} else if input.WorkerNum <= 0 {
		return nil, fmt.Errorf("worker number cannot be <= 0")
	}
	return &AggregationProcess{
		make(map[FlowKey][]entities.Record),
		sync.RWMutex{},
		input.MessageChan,
		input.WorkerNum,
		make([]*worker, 0),
		input.CorrelateFields,
		make(chan bool),
	}, nil
}

func (a *AggregationProcess) Start() {
	a.mutex.Lock()
	for i := 0; i < a.workerNum; i++ {
		w := createWorker(i, a.messageChan, a.AggregateMsgByFlowKey)
		w.start()
		a.workerList = append(a.workerList, w)
	}
	a.mutex.Unlock()
	<-a.stopChan
}

func (a *AggregationProcess) Stop() {
	a.mutex.Lock()
	for _, worker := range a.workerList {
		worker.stop()
	}
	a.mutex.Unlock()
	a.stopChan <- true
}

// AggregateMsgByFlowKey gets flow key from records in message and stores in cache
func (a *AggregationProcess) AggregateMsgByFlowKey(message *entities.Message) error {
	if err := addOriginalExporterInfo(message); err != nil {
		return err
	}
	set := message.GetSet()
	if set.GetSetType() == entities.Template { // skip template records
		return nil
	}
	records := set.GetRecords()
	for _, record := range records {
		flowKey, err := getFlowKeyFromRecord(record)
		if err != nil {
			return err
		}
		a.correlateRecords(*flowKey, record)
	}
	return nil
}

// ForAllRecordsDo takes in callback function to process the operations to flowkey->records pairs in the map
func (a *AggregationProcess) ForAllRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	for k, v := range a.flowKeyRecordMap {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Callback execution failed for flow with key: %v, records: %v, error: %v", k, v, err)
			return err
		}
	}
	return nil
}

func (a *AggregationProcess) DeleteFlowKeyFromMap(flowKey FlowKey) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.flowKeyRecordMap, flowKey)
}

// correlateRecords fills records info by correlating incoming and current records
func (a *AggregationProcess) correlateRecords(flowKey FlowKey, record entities.Record) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	existingRecords := a.flowKeyRecordMap[flowKey]
	// only fill the information for record from source node
	if isRecordFromSrc(record) {
		var isFilled bool
		for _, existingRec := range existingRecords {
			for _, field := range a.correlateFields {
				if ieWithValue, exist := record.GetInfoElementWithValue(field); exist {
					existingIeWithValue, _ := existingRec.GetInfoElementWithValue(field)
					ieWithValue.Value = existingIeWithValue.Value
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
					if ieWithValue, exist := record.GetInfoElementWithValue(field); exist {
						existingIeWithValue, _ := existingRec.GetInfoElementWithValue(field)
						existingIeWithValue.Value = ieWithValue.Value
					}
				}
			}
		}
	}
	a.addRecordToMap(flowKey, record)
	a.removeDuplicates(flowKey)
}

// removeDuplicates is currently used only in correlateRecords().
// For other uses, please acquire the flowKeyRecordLock for protection.
func (a *AggregationProcess) removeDuplicates(flowKey FlowKey) {
	records := a.flowKeyRecordMap[flowKey]
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
		a.flowKeyRecordMap[flowKey] = srcRecords
	} else {
		a.flowKeyRecordMap[flowKey] = dstRecords
	}
}

// addRecordToMap is currently used only in correlateRecords().
// For other uses, please acquire the flowKeyRecordLock for protection.
func (a *AggregationProcess) addRecordToMap(flowKey FlowKey, record entities.Record) {
	if _, exist := a.flowKeyRecordMap[flowKey]; !exist {
		a.flowKeyRecordMap[flowKey] = make([]entities.Record, 0)
	}
	a.flowKeyRecordMap[flowKey] = append(a.flowKeyRecordMap[flowKey], record)
}

func isRecordFromSrc(record entities.Record) bool {
	ieWithValue, exist := record.GetInfoElementWithValue("sourcePodName")
	if exist && ieWithValue.Value != "" {
		return true
	}
	return false
}

// getFlowKeyFromRecord returns 5-tuple from data record
func getFlowKeyFromRecord(record entities.Record) (*FlowKey, error) {
	flowKey := &FlowKey{}
	elementList := []string{
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceIPv6Address",
		"destinationIPv6Address",
	}
	var isSrcIPv4Filled, isDstIPv4Filled bool
	for _, name := range elementList {
		switch name {
		case "sourceTransportPort", "destinationTransportPort":
			element, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, fmt.Errorf("%s does not exist", name)
			}
			port, ok := element.Value.(uint16)
			if !ok {
				return nil, fmt.Errorf("%s is not in correct format", name)
			}
			if name == "sourceTransportPort" {
				flowKey.SourcePort = port
			} else {
				flowKey.DestinationPort = port
			}
		case "sourceIPv4Address", "destinationIPv4Address":
			element, exist := record.GetInfoElementWithValue(name)
			if !exist {
				break
			}
			addr, ok := element.Value.(net.IP)
			if !ok {
				return nil, fmt.Errorf("%s is not in correct format", name)
			}

			if strings.Contains(name, "source") {
				isSrcIPv4Filled = true
				flowKey.SourceAddress = addr.String()
			} else {
				isDstIPv4Filled = true
				flowKey.DestinationAddress = addr.String()
			}
		case "sourceIPv6Address", "destinationIPv6Address":
			element, exist := record.GetInfoElementWithValue(name)
			if (isSrcIPv4Filled && strings.Contains(name, "source")) || (isDstIPv4Filled && strings.Contains(name, "destination")) {
				if exist {
					klog.Warning("Two ip versions (IPv4 and IPv6) are not supported for flow key.")
				}
				break
			}
			if !exist {
				return nil, fmt.Errorf("%s does not exist", name)
			}
			addr, ok := element.Value.(net.IP)
			if !ok {
				return nil, fmt.Errorf("%s is not in correct format", name)
			}
			if strings.Contains(name, "source") {
				flowKey.SourceAddress = addr.String()
			} else {
				flowKey.DestinationAddress = addr.String()
			}
		case "protocolIdentifier":
			element, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, fmt.Errorf("%s does not exist", name)
			}
			proto, ok := element.Value.(uint8)
			if !ok {
				return nil, fmt.Errorf("%s is not in correct format: %v", name, proto)
			}
			flowKey.Protocol = proto
		}
	}
	return flowKey, nil
}

// addOriginalExporterInfo adds originalExporterIP and originalObservationDomainId to records in message set
func addOriginalExporterInfo(message *entities.Message) error {
	isIPv4 := false
	exporterIP := net.ParseIP(message.GetExportAddress())
	if exporterIP.To4() != nil {
		isIPv4 = true
	}
	set := message.GetSet()
	records := set.GetRecords()
	for _, record := range records {
		var originalExporterIP, originalObservationDomainId *entities.InfoElementWithValue
		var ie *entities.InfoElement
		var err error
		// Add originalExporterIP. Supports both IPv4 and IPv6.
		if isIPv4 {
			ie, err = registry.GetInfoElement("originalExporterIPv4Address", registry.IANAEnterpriseID)
		} else {
			ie, err = registry.GetInfoElement("originalExporterIPv6Address", registry.IANAEnterpriseID)
		}
		if err != nil {
			return err
		}

		if set.GetSetType() == entities.Template {
			originalExporterIP = entities.NewInfoElementWithValue(ie, nil)
		} else if set.GetSetType() == entities.Data {
			originalExporterIP = entities.NewInfoElementWithValue(ie, net.ParseIP(message.GetExportAddress()))
		} else {
			return fmt.Errorf("set type %d is not supported", set.GetSetType())
		}
		_, err = record.AddInfoElement(originalExporterIP, false)
		if err != nil {
			return err
		}

		// Add originalObservationDomainId
		ie, err = registry.GetInfoElement("originalObservationDomainId", registry.IANAEnterpriseID)
		if err != nil {
			return fmt.Errorf("IANA Registry is not loaded correctly with originalObservationDomainId")
		}
		if set.GetSetType() == entities.Template {
			originalObservationDomainId = entities.NewInfoElementWithValue(ie, nil)
		} else if set.GetSetType() == entities.Data {
			originalObservationDomainId = entities.NewInfoElementWithValue(ie, message.GetObsDomainID())
		} else {
			return fmt.Errorf("set type %d is not supported", set.GetSetType())
		}
		_, err = record.AddInfoElement(originalObservationDomainId, false)
		if err != nil {
			return err
		}
	}
	return nil
}
