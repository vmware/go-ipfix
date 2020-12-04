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
	flowKeyRecordMap map[FlowKey]AggregationFlowRecord
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

type AggregationFlowRecord struct {
	Record entities.Record
	// ReadyToSend is an indicator that we received all required records for the
	// given flow, i.e., records from source and destination nodes for the case
	// inter-node flow and record from the node for the case of intra-node flow.
	ReadyToSend bool
	// IsActive is a flag that indicates whether the flow is active or not. If
	// aggregation process stop receiving flows from collector process, we deem
	// the flow as inactive.
	IsActive bool
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
		make(map[FlowKey]AggregationFlowRecord),
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
		a.aggregateRecord(flowKey, record)
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

// aggregateRecord either adds the record to flowKeyMap or update the record in
// flowKeyMap by doing correlation or updating the stats.
func (a *AggregationProcess) aggregateRecord(flowKey *FlowKey, record entities.Record) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	aggregationRecord, exist := a.flowKeyRecordMap[*flowKey]
	if exist {
		if !isRecordIntraNode(record) {
			// Do correlation of records if record belongs to inter-node flow and
			// records from source and destination node are not received.
			if !aggregationRecord.ReadyToSend && !areRecordsFromSameNode(record, aggregationRecord.Record) {
				a.correlateRecords(record, aggregationRecord.Record)
				aggregationRecord.ReadyToSend = true
			} else {
				// If the record from the node is already present, update the stats
				// and timestamps.
			}
		} else {
			// For intra-node flows, just do aggregation of the flow record with
			// existing record by updating the stats and flow timestamps. Correlation
			// is not required.

		}

	} else {
		aggregationRecord = AggregationFlowRecord{
			record,
			false,
			true,
		}
		if isRecordIntraNode(record) {
			aggregationRecord.ReadyToSend = true
		}
	}

	a.addRecordToMap(flowKey, aggregationRecord)
}

// correlateRecords correlate the incomingRecord with existingRecord using correlation
// fields.
func (a *AggregationProcess) correlateRecords(incomingRecord, existingRecord entities.Record) {
	for _, field := range a.correlateFields {
		if ieWithValue, exist := incomingRecord.GetInfoElementWithValue(field); exist {
			switch ieWithValue.Element.DataType {
			case entities.String:
				if ieWithValue.Value != "" {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					if existingIeWithValue.Value != "" {
						klog.Warningf("This field with name %v should not have been filled with value %v in existing record.", field, existingIeWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Unsigned16:
				if  ieWithValue.Value != uint16(0) {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					if existingIeWithValue.Value != uint16(0) {
						klog.Warningf("This field with name %v should not have been filled with value %v in existing record.", field, existingIeWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Ipv4Address:
				ipInString := ieWithValue.Value.(net.IP).To4().String()
				if ipInString != "0.0.0.0" {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					ipInString := existingIeWithValue.Value.(net.IP).To4().String()
					if ipInString != "0.0.0.0" {
						klog.Warningf("This field with name %v should not have been filled with value %v in existing record.", field, existingIeWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Ipv6Address:
				ipInString := ieWithValue.Value.(net.IP).To16().String()
				if ipInString != net.ParseIP("::0").To16().String() {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					ipInString := existingIeWithValue.Value.(net.IP).To16().String()
					if ipInString != net.ParseIP("::0").To16().String() {
						klog.Warningf("This field with name %v should not have been filled with value %v in existing record.", field, existingIeWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			default:
				klog.Errorf("Fields with dataType %v is not supported in correlation fields list.", ieWithValue.Element.DataType)
			}
		}
	}
}

// addRecordToMap is currently used only in aggregateRecord().
// For other uses, please acquire the flowKeyRecordLock for protection.
func (a *AggregationProcess) addRecordToMap(flowKey *FlowKey, record AggregationFlowRecord) {
	if _, exist := a.flowKeyRecordMap[*flowKey]; !exist {
		a.flowKeyRecordMap[*flowKey] = record
	}
}

// isRecordIntraNode returns true if record belongs to intra-node flow.
func isRecordIntraNode(record entities.Record) bool {
	srcIEWithValue, exist := record.GetInfoElementWithValue("sourcePodName")
	if exist && srcIEWithValue.Value != "" {
		dstIEWithValue, exist := record.GetInfoElementWithValue("destinationPodName")
		if exist && dstIEWithValue.Value != "" {
			return true
		}
	}
	return false
}

// isRecordFromSrc returns true if record belongs to inter-node flow and from source node.
func isRecordFromSrc(record entities.Record) bool {
	if isRecordIntraNode(record) {
		return false
	}
	ieWithValue, exist := record.GetInfoElementWithValue("destinationPodName")
	if exist && ieWithValue.Value == "" {
		return true
	}
	return false
}

// isRecordFromDst returns true if record belongs to inter-node flow and from destination node.
func isRecordFromDst(record entities.Record) bool {
	if isRecordIntraNode(record) {
		return false
	}
	ieWithValue, exist := record.GetInfoElementWithValue("sourcePodName")
	if exist && ieWithValue.Value == "" {
		return true
	}
	return false
}

func areRecordsFromSameNode(record1 entities.Record, record2 entities.Record) bool {
	// If records belong to intra-node flow, then send true.
	if isRecordIntraNode(record1) && isRecordIntraNode(record2) {
		return true
	}
	// If records belong to inter-node flow and are from source node, then send true.
	if isRecordFromSrc(record1) && isRecordFromSrc(record2) {
		return true
	}
	// If records belong to inter-node flow and are from destination node, then send true.
	if isRecordFromDst(record1) && isRecordFromDst(record2) {
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
