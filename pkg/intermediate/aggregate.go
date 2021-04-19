// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intermediate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
	"github.com/vmware/go-ipfix/pkg/util"
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
	// correlateFields are the fields to be filled when correlating records of the
	// flow whose type is registry.InterNode(pkg/registry/registry.go).
	correlateFields []string
	// aggregateElements consists of stats and non-stats elements that need to be
	// updated. In addition, new aggregation elements that has to be added to record
	// to handle correlated records from two nodes should be given.
	// TODO: Add checks to validate the lists inside such as no duplicates, order
	// of stats etc.
	aggregateElements *AggregationElements
	// stopChan is the channel to receive stop message
	stopChan chan bool
}

type AggregationInput struct {
	MessageChan       chan *entities.Message
	WorkerNum         int
	CorrelateFields   []string
	AggregateElements *AggregationElements
}

// InitAggregationProcess takes in message channel (e.g. from collector) as input
// channel, workerNum(number of workers to process message), and
// correlateFields(fields to be correlated and filled).
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
		input.AggregateElements,
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
	invalidRecs := 0
	for _, record := range records {
		// Validate the data record. If invalid, we log the error and move to the next
		// record.
		if !validateDataRecord(record) {
			klog.Errorf("Invalid data record because decoded values of elements are not valid.")
			invalidRecs = invalidRecs + 1
		} else {
			flowKey, err := getFlowKeyFromRecord(record)
			if err != nil {
				return err
			}
			if err = a.addOrUpdateRecordInMap(flowKey, record); err != nil {
				return err
			}
		}
	}
	if invalidRecs == len(records) {
		return fmt.Errorf("all data records in the message are invalid")
	}
	return nil
}

// ForAllRecordsDo takes in callback function to process the operations to flowkey->records pairs in the map
func (a *AggregationProcess) ForAllRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for k, v := range a.flowKeyRecordMap {
		err := callback(k, v)
		if err != nil {
			klog.Errorf("Callback execution failed for flow with key: %v, records: %v, error: %v", k, v, err)
			return err
		}
	}
	return nil
}

func (a *AggregationProcess) DeleteFlowKeyFromMapWithLock(flowKey FlowKey) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	delete(a.flowKeyRecordMap, flowKey)
}

// DeleteFlowKeyFromMapWithoutLock need to be used only when the caller has already
// acquired the lock. For example, this can be used in a callback of ForAllRecordsDo
// function.
// TODO:Remove this when there is notion of invalid flows supported in aggregation
// process.
func (a *AggregationProcess) DeleteFlowKeyFromMapWithoutLock(flowKey FlowKey) {
	delete(a.flowKeyRecordMap, flowKey)
}

// addOrUpdateRecordInMap either adds the record to flowKeyMap or updates the record in
// flowKeyMap by doing correlation or updating the stats.
func (a *AggregationProcess) addOrUpdateRecordInMap(flowKey *FlowKey, record entities.Record) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	correlationRequired := isCorrelationRequired(record)

	aggregationRecord, exist := a.flowKeyRecordMap[*flowKey]
	if exist {
		if correlationRequired {
			// Do correlation of records if record belongs to inter-node flow and
			// records from source and destination node are not received.
			if !aggregationRecord.ReadyToSend && !areRecordsFromSameNode(record, aggregationRecord.Record) {
				a.correlateRecords(record, aggregationRecord.Record)
				aggregationRecord.ReadyToSend = true
			}
			// Aggregation of incoming flow record with existing by updating stats
			// and flow timestamps.
			if isRecordFromSrc(record) {
				if err := a.aggregateRecords(record, aggregationRecord.Record, true, false); err != nil {
					return err
				}
			} else {
				if err := a.aggregateRecords(record, aggregationRecord.Record, false, true); err != nil {
					return err
				}
			}
		} else {
			// For flows that do not need correlation, just do aggregation of the
			// flow record with existing record by updating the stats and flow timestamps.
			if err := a.aggregateRecords(record, aggregationRecord.Record, true, true); err != nil {
				return err
			}
		}
	} else {
		// Add all the new stat fields and initialize them.
		if correlationRequired {
			if isRecordFromSrc(record) {
				if err := a.addFieldsForStatsAggregation(record, true, false); err != nil {
					return err
				}
			} else {
				if err := a.addFieldsForStatsAggregation(record, false, true); err != nil {
					return err
				}
			}
		} else {
			if err := a.addFieldsForStatsAggregation(record, true, true); err != nil {
				return err
			}
		}
		aggregationRecord = AggregationFlowRecord{
			record,
			false,
			true,
		}
		if !correlationRequired {
			aggregationRecord.ReadyToSend = true
		}
	}

	a.flowKeyRecordMap[*flowKey] = aggregationRecord
	return nil
}

// correlateRecords correlate the incomingRecord with existingRecord using correlation
// fields. This is called for records whose flowType is InterNode(pkg/registry/registry.go).
func (a *AggregationProcess) correlateRecords(incomingRecord, existingRecord entities.Record) {
	for _, field := range a.correlateFields {
		if ieWithValue, exist := incomingRecord.GetInfoElementWithValue(field); exist {
			switch ieWithValue.Element.DataType {
			case entities.String:
				if ieWithValue.Value != "" {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					if existingIeWithValue.Value != "" {
						klog.Warningf("%v field should not have been filled in the existing record; existing value: %v and current value: %v", field, existingIeWithValue.Value, ieWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Unsigned8:
				if ieWithValue.Value != uint8(0) {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					if existingIeWithValue.Value != uint8(0) {
						klog.Warningf("%v field should not have been filled in the existing record; existing value: %v and current value: %v", field, existingIeWithValue.Value, ieWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Unsigned16:
				if ieWithValue.Value != uint16(0) {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					if existingIeWithValue.Value != uint16(0) {
						klog.Warningf("%v field should not have been filled in the existing record; existing value: %v and current value: %v", field, existingIeWithValue.Value, ieWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Ipv4Address:
				ipInString := ieWithValue.Value.(net.IP).To4().String()
				if ipInString != "0.0.0.0" {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					ipInString = existingIeWithValue.Value.(net.IP).To4().String()
					if ipInString != "0.0.0.0" {
						klog.Warningf("%v field should not have been filled in the existing record; existing value: %v and current value: %v", field, existingIeWithValue.Value, ieWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			case entities.Ipv6Address:
				ipInString := ieWithValue.Value.(net.IP).To16().String()
				if ipInString != net.ParseIP("::0").To16().String() {
					existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(field)
					ipInString = existingIeWithValue.Value.(net.IP).To16().String()
					if ipInString != net.ParseIP("::0").To16().String() {
						klog.Warningf("%v field should not have been filled in the existing record; existing value: %v and current value: %v", field, existingIeWithValue.Value, ieWithValue.Value)
					}
					existingIeWithValue.Value = ieWithValue.Value
				}
			default:
				klog.Errorf("Fields with dataType %v is not supported in correlation fields list.", ieWithValue.Element.DataType)
			}
		}
	}
}

// aggregateRecords aggregate the incomingRecord with existingRecord by updating
// stats and flow timestamps.
func (a *AggregationProcess) aggregateRecords(incomingRecord, existingRecord entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	isLatest := false
	if ieWithValue, exist := incomingRecord.GetInfoElementWithValue("flowEndSeconds"); exist {
		if existingIeWithValue, exist2 := existingRecord.GetInfoElementWithValue("flowEndSeconds"); exist2 {
			if ieWithValue.Value.(uint32) > existingIeWithValue.Value.(uint32) {
				isLatest = true
			}
		}
	}
	for _, element := range a.aggregateElements.NonStatsElements {
		if ieWithValue, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(element)
			switch ieWithValue.Element.Name {
			case "flowEndSeconds":
				// Update flow end timestamp if it is latest.
				if isLatest {
					existingIeWithValue.Value = ieWithValue.Value
				}
			case "flowEndReason":
				// If the aggregated flow is set with flowEndReason as "EndOfFlowReason",
				// then we do not have to set again.
				if existingIeWithValue.Value.(uint8) != registry.EndOfFlowReason {
					existingIeWithValue.Value = ieWithValue.Value
				}
			case "tcpState":
				// Update tcpState when flow end timestamp is the latest
				if isLatest {
					existingIeWithValue.Value = ieWithValue.Value
				}
			default:
				klog.Errorf("Fields with name %v is not supported in aggregation fields list.", element)
			}
		} else {
			return fmt.Errorf("element with name %v in nonStatsElements not present in the incoming record", element)
		}
	}

	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements
	for i, element := range statsElementList {
		isDelta := false
		if strings.Contains(element, "Delta") {
			isDelta = true
		}
		if ieWithValue, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			existingIeWithValue, _ := existingRecord.GetInfoElementWithValue(element)
			// Update the corresponding element in existing record.
			if !isDelta {
				if existingIeWithValue.Value.(uint64) < ieWithValue.Value.(uint64) {
					existingIeWithValue.Value = ieWithValue.Value
				}
			} else {
				// We are simply adding the delta stats now. We expect delta stats to be
				// reset after sending the record from flowKeyMap in aggregation process.
				// Delta stats from source and destination nodes are added, so we will have
				// two times the stats approximately.
				// For delta stats, it is better to use source and destination specific
				// stats.
				existingIeWithValue.Value = existingIeWithValue.Value.(uint64) + ieWithValue.Value.(uint64)
			}
			// Update the corresponding source element in antreaStatsElement list.
			if fillSrcStats {
				existingIeWithValue, _ = existingRecord.GetInfoElementWithValue(antreaSourceStatsElements[i])
				if !isDelta {
					existingIeWithValue.Value = ieWithValue.Value
				} else {
					existingIeWithValue.Value = existingIeWithValue.Value.(uint64) + ieWithValue.Value.(uint64)
				}
			}
			// Update the corresponding destination element in antreaStatsElement list.
			if fillDstStats {
				existingIeWithValue, _ = existingRecord.GetInfoElementWithValue(antreaDestinationStatsElements[i])
				if !isDelta {
					existingIeWithValue.Value = ieWithValue.Value
				} else {
					existingIeWithValue.Value = existingIeWithValue.Value.(uint64) + ieWithValue.Value.(uint64)
				}
			}
		} else {
			return fmt.Errorf("element with name %v in statsElements not present in the incoming record", element)
		}
	}
	return nil
}

func (a *AggregationProcess) addFieldsForStatsAggregation(record entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements
	antreaElements := append(antreaSourceStatsElements, antreaDestinationStatsElements...)

	for _, element := range antreaElements {
		// Get the new info element from Antrea registry.
		// TODO: Take antrea registry enterpriseID as input to make this generic.
		ie, err := registry.GetInfoElement(element, registry.AntreaEnterpriseID)
		if err != nil {
			return err
		}
		value := new(bytes.Buffer)
		if err = util.Encode(value, binary.BigEndian, uint64(0)); err != nil {
			return err
		}
		ieWithValue := entities.NewInfoElementWithValue(ie, value)
		_, err = record.AddInfoElement(ieWithValue, true)
		if err != nil {
			return err
		}
	}
	// Initialize the values of newly added stats info elements.
	for i, element := range statsElementList {
		if ieWithValue, exist := record.GetInfoElementWithValue(element); exist {
			// Initialize the corresponding source element in antreaStatsElement list.
			if fillSrcStats {
				existingIeWithValue, _ := record.GetInfoElementWithValue(antreaSourceStatsElements[i])
				existingIeWithValue.Value = ieWithValue.Value
			}
			// Initialize the corresponding destination element in antreaStatsElement list.
			if fillDstStats {
				existingIeWithValue, _ := record.GetInfoElementWithValue(antreaDestinationStatsElements[i])
				existingIeWithValue.Value = ieWithValue.Value
			}
		}
	}
	return nil
}

// isRecordFromSrc returns true if record belongs to inter-node flow and from source node.
func isRecordFromSrc(record entities.Record) bool {
	srcIEWithValue, exist := record.GetInfoElementWithValue("sourcePodName")
	if !exist || srcIEWithValue.Value == "" {
		return false
	}
	dstIEWithValue, exist := record.GetInfoElementWithValue("destinationPodName")
	if exist && dstIEWithValue.Value != "" {
		return false
	}
	return true
}

// isRecordFromDst returns true if record belongs to inter-node flow and from destination node.
func isRecordFromDst(record entities.Record) bool {
	dstIEWithValue, exist := record.GetInfoElementWithValue("destinationPodName")
	if !exist || dstIEWithValue.Value == "" {
		return false
	}
	srcIEWithValue, exist := record.GetInfoElementWithValue("sourcePodName")
	if exist && srcIEWithValue.Value != "" {
		return false
	}
	return true
}

func areRecordsFromSameNode(record1 entities.Record, record2 entities.Record) bool {
	// If both records of inter-node flow are from source node, then send true.
	if isRecordFromSrc(record1) && isRecordFromSrc(record2) {
		return true
	}
	// If both records of inter-node flow are from destination node, then send true.
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

func validateDataRecord(record entities.Record) bool {
	for _, element := range record.GetOrderedElementList() {
		if element.Value == nil {
			// All element values should have been filled after decoding.
			// If not, it is an invalid data record.
			return false
		}
	}
	return true
}

// isCorrelationRequired returns true for InterNode flowType when
// either the egressNetworkPolicyRuleAction is not deny (drop/reject) or
// the ingressNetworkPolicyRuleAction is not reject.
func isCorrelationRequired(record entities.Record) bool {
	if ieWithValue, exist := record.GetInfoElementWithValue("flowType"); exist {
		if recordFlowType, ok := ieWithValue.Value.(uint8); ok {
			if recordFlowType == registry.FlowTypeInterNode {
				if egressRuleActionIe, exist := record.GetInfoElementWithValue("egressNetworkPolicyRuleAction"); exist {
					if egressRuleAction, ok := egressRuleActionIe.Value.(uint8); ok {
						if egressRuleAction == registry.NetworkPolicyRuleActionDrop || egressRuleAction == registry.NetworkPolicyRuleActionReject {
							return false
						}
					}
				}
				if ingressRuleActionIe, exist := record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction"); exist {
					if ingressRuleAction, ok := ingressRuleActionIe.Value.(uint8); ok {
						if ingressRuleAction == registry.NetworkPolicyRuleActionReject {
							return false
						}
					}
				}
				return true
			}
		}
	}
	return false
}
