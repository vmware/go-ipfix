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
	"container/heap"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/registry"
)

var (
	MaxRetries    = 2
	MinExpiryTime = 100 * time.Millisecond
)

type AggregationProcess struct {
	// flowKeyRecordMap maps each connection (5-tuple) with its records
	flowKeyRecordMap map[FlowKey]*AggregationFlowRecord
	// expirePriorityQueue helps to maintain a priority queue for the records given
	// active expiry and inactive expiry timeouts.
	expirePriorityQueue TimeToExpirePriorityQueue
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
	// activeExpiryTimeout helps in identifying records that elapsed active expiry
	// timeout. Active expiry timeout is a periodic expiry interval for every flow
	// record in the aggregation record map.
	activeExpiryTimeout time.Duration
	// inactiveExpiryTimeout helps in identifying records that elapsed inactive expiry
	// timeout. Inactive expiry timeout is an expiry interval that gets reset every
	// time a new record is received for the existing record in the aggregation
	// record map.
	inactiveExpiryTimeout time.Duration
	// stopChan is the channel to receive stop message
	stopChan chan bool
}

type AggregationInput struct {
	MessageChan           chan *entities.Message
	WorkerNum             int
	CorrelateFields       []string
	AggregateElements     *AggregationElements
	ActiveExpiryTimeout   time.Duration
	InactiveExpiryTimeout time.Duration
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
	if input.AggregateElements != nil {
		if (len(input.AggregateElements.StatsElements) != len(input.AggregateElements.AggregatedSourceStatsElements)) || (len(input.AggregateElements.StatsElements) != len(input.AggregateElements.AggregatedDestinationStatsElements)) {
			return nil, fmt.Errorf("stats elements, source stats elements and destination stats elemenst length should be equal")
		}
	}
	return &AggregationProcess{
		make(map[FlowKey]*AggregationFlowRecord),
		make(TimeToExpirePriorityQueue, 0),
		sync.RWMutex{},
		input.MessageChan,
		input.WorkerNum,
		make([]*worker, 0),
		input.CorrelateFields,
		input.AggregateElements,
		input.ActiveExpiryTimeout,
		input.InactiveExpiryTimeout,
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
	set := message.GetSet()
	if set.GetSetType() != entities.Data { // only process data records
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
			flowKey, isIPv4, err := getFlowKeyFromRecord(record)
			if err != nil {
				return err
			}
			if err = a.addOrUpdateRecordInMap(flowKey, record, isIPv4); err != nil {
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

func (a *AggregationProcess) deleteFlowKeyFromMap(flowKey FlowKey) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.deleteFlowKeyFromMapWithoutLock(flowKey)
}

func (a *AggregationProcess) deleteFlowKeyFromMapWithoutLock(flowKey FlowKey) error {
	_, exists := a.flowKeyRecordMap[flowKey]
	if !exists {
		return fmt.Errorf("flow key %v is not present in the map", flowKey)
	}
	delete(a.flowKeyRecordMap, flowKey)
	return nil
}

// GetExpiryFromExpirePriorityQueue returns the earliest timestamp (active expiry
// or inactive expiry) from expire priority queue.
func (a *AggregationProcess) GetExpiryFromExpirePriorityQueue() time.Duration {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	currTime := time.Now()
	if a.expirePriorityQueue.Len() > 0 {
		// Get the minExpireTime of the top item in expirePriorityQueue.
		expiryDuration := MinExpiryTime + a.expirePriorityQueue.minExpireTime(0).Sub(currTime)
		if expiryDuration < 0 {
			return MinExpiryTime
		}
		return expiryDuration
	}
	if a.activeExpiryTimeout < a.inactiveExpiryTimeout {
		return a.activeExpiryTimeout
	}
	return a.inactiveExpiryTimeout
}

func (a *AggregationProcess) ForAllExpiredFlowRecordsDo(callback FlowKeyRecordMapCallBack) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.expirePriorityQueue.Len() == 0 {
		return nil
	}
	currTime := time.Now()
	for a.expirePriorityQueue.Len() > 0 {
		topItem := a.expirePriorityQueue.Peek()
		if topItem.activeExpireTime.After(currTime) && topItem.inactiveExpireTime.After(currTime) {
			// We do not have to check other items anymore.
			break
		}
		// Pop the record item from the priority queue
		pqItem := heap.Pop(&a.expirePriorityQueue).(*ItemToExpire)
		if !pqItem.flowRecord.ReadyToSend {
			// Reset the timeouts and add the record to priority queue.
			// Delete the record after max retries.
			pqItem.flowRecord.waitForReadyToSendRetries = pqItem.flowRecord.waitForReadyToSendRetries + 1
			if pqItem.flowRecord.waitForReadyToSendRetries > MaxRetries {
				klog.V(2).Infof("Deleting the record after waiting for ready to send with key: %v record: %v", pqItem.flowKey, pqItem.flowRecord)
				if err := a.deleteFlowKeyFromMapWithoutLock(*pqItem.flowKey); err != nil {
					return fmt.Errorf("error while deleting flow record after max retries: %v", err)
				}
			} else {
				pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
				pqItem.inactiveExpireTime = currTime.Add(a.inactiveExpiryTimeout)
				heap.Push(&a.expirePriorityQueue, pqItem)
			}
			continue
		}
		err := callback(*pqItem.flowKey, pqItem.flowRecord)
		if err != nil {
			return fmt.Errorf("callback execution failed for popped flow record with key: %v, record: %v, error: %v", pqItem.flowKey, pqItem.flowRecord, err)
		}
		// Delete the flow record if it is expired because of inactive expiry timeout.
		if pqItem.inactiveExpireTime.Before(currTime) {
			if err = a.deleteFlowKeyFromMapWithoutLock(*pqItem.flowKey); err != nil {
				return fmt.Errorf("error while deleting flow record after inactive expiry: %v", err)
			}
			continue
		}
		// Reset the expireTime for the popped item and push it to the priority queue.
		if pqItem.activeExpireTime.Before(currTime) {
			// Reset the active expire timeout and push the record into priority
			// queue.
			pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
			heap.Push(&a.expirePriorityQueue, pqItem)
		}
	}
	return nil
}

func (a *AggregationProcess) SetCorrelatedFieldsFilled(record *AggregationFlowRecord, isFilled bool) {
	record.areCorrelatedFieldsFilled = isFilled
}

func (a *AggregationProcess) AreCorrelatedFieldsFilled(record AggregationFlowRecord) bool {
	return record.areCorrelatedFieldsFilled
}

func (a *AggregationProcess) SetExternalFieldsFilled(record *AggregationFlowRecord, isFilled bool) {
	record.areExternalFieldsFilled = isFilled
}

func (a *AggregationProcess) AreExternalFieldsFilled(record AggregationFlowRecord) bool {
	return record.areExternalFieldsFilled
}

func (a *AggregationProcess) IsAggregatedRecordIPv4(record AggregationFlowRecord) bool {
	return record.isIPv4
}

// addOrUpdateRecordInMap either adds the record to flowKeyMap or updates the record in
// flowKeyMap by doing correlation or updating the stats.
func (a *AggregationProcess) addOrUpdateRecordInMap(flowKey *FlowKey, record entities.Record, isIPv4 bool) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	var flowType uint8
	var err error
	if flowTypeIE, _, exist := record.GetInfoElementWithValue("flowType"); exist {
		if flowType, err = flowTypeIE.GetUnsigned8Value(); err != nil {
			return err
		}
	} else {
		klog.Warning("FlowType does not exist in current record.")
	}
	correlationRequired := isCorrelationRequired(flowType, record)

	currTime := time.Now()
	aggregationRecord, exist := a.flowKeyRecordMap[*flowKey]
	if exist {
		if correlationRequired {
			// Do correlation of records if record belongs to inter-node flow and
			// records from source and destination node are not received.
			if !aggregationRecord.ReadyToSend && !areRecordsFromSameNode(record, aggregationRecord.Record) {
				if err = a.correlateRecords(record, aggregationRecord.Record); err != nil {
					return err
				}
				aggregationRecord.ReadyToSend = true
				aggregationRecord.areCorrelatedFieldsFilled = true
			}
			// Aggregation of incoming flow record with existing by updating stats
			// and flow timestamps.
			if isRecordFromSrc(record) {
				if err = a.aggregateRecords(record, aggregationRecord.Record, true, false); err != nil {
					return err
				}
			} else {
				if err = a.aggregateRecords(record, aggregationRecord.Record, false, true); err != nil {
					return err
				}
			}
		} else {
			// For flows that do not need correlation, just do aggregation of the
			// flow record with existing record by updating the stats and flow timestamps.
			if err = a.aggregateRecords(record, aggregationRecord.Record, true, true); err != nil {
				return err
			}
		}
		// Reset the inactive expiry time in the queue item with updated aggregate
		// record.
		a.expirePriorityQueue.Update(aggregationRecord.PriorityQueueItem,
			flowKey, aggregationRecord, aggregationRecord.PriorityQueueItem.activeExpireTime, currTime.Add(a.inactiveExpiryTimeout))
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
		aggregationRecord = &AggregationFlowRecord{
			Record:                    record,
			ReadyToSend:               false,
			waitForReadyToSendRetries: 0,
			isIPv4:                    isIPv4,
		}

		if !correlationRequired {
			aggregationRecord.ReadyToSend = true
			// If no correlation is required for an Inter-Node record, K8s metadata is
			// expected to be not completely filled. For Intra-Node flows and ToExternal
			// flows, areCorrelatedFieldsFilled is set to true by default.
			if flowType == registry.FlowTypeInterNode {
				aggregationRecord.areCorrelatedFieldsFilled = false
			} else {
				aggregationRecord.areCorrelatedFieldsFilled = true
			}
		}
		aggregationRecord.areExternalFieldsFilled = false
		// Push the record to the priority queue.
		pqItem := &ItemToExpire{
			flowKey: flowKey,
		}
		aggregationRecord.PriorityQueueItem = pqItem

		pqItem.flowRecord = aggregationRecord
		pqItem.activeExpireTime = currTime.Add(a.activeExpiryTimeout)
		pqItem.inactiveExpireTime = currTime.Add(a.inactiveExpiryTimeout)
		heap.Push(&a.expirePriorityQueue, pqItem)
	}
	a.flowKeyRecordMap[*flowKey] = aggregationRecord
	return nil
}

// correlateRecords correlate the incomingRecord with existingRecord using correlation
// fields. This is called for records whose flowType is InterNode(pkg/registry/registry.go).
func (a *AggregationProcess) correlateRecords(incomingRecord, existingRecord entities.Record) error {
	for _, field := range a.correlateFields {
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(field); exist {
			element := ieWithValue.GetInfoElement()
			switch element.DataType {
			case entities.String:
				val, err := ieWithValue.GetStringValue()
				if err != nil {
					return err
				}
				if val != "" {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetStringValue(val); err != nil {
						return err
					}
				}
			case entities.Unsigned8:
				val, err := ieWithValue.GetUnsigned8Value()
				if err != nil {
					return err
				}
				if val != uint8(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetUnsigned8Value(val); err != nil {
						return err
					}
				}
			case entities.Unsigned16:
				val, err := ieWithValue.GetUnsigned16Value()
				if err != nil {
					return err
				}
				if val != uint16(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetUnsigned16Value(val); err != nil {
						return err
					}
				}
			case entities.Signed32:
				val, err := ieWithValue.GetSigned32Value()
				if err != nil {
					return err
				}
				if val != int32(0) {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetSigned32Value(val); err != nil {
						return err
					}
				}
			case entities.Ipv4Address:
				val, err := ieWithValue.GetIPAddressValue()
				if err != nil {
					return err
				}
				ipInString := val.To4().String()
				if ipInString != "0.0.0.0" {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetIPAddressValue(val); err != nil {
						return err
					}
				}
			case entities.Ipv6Address:
				val, err := ieWithValue.GetIPAddressValue()
				if err != nil {
					return err
				}
				ipInString := val.To16().String()
				if ipInString != net.ParseIP("::0").To16().String() {
					existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(field)
					if err = existingIeWithValue.SetIPAddressValue(val); err != nil {
						return err
					}
				}
			default:
				klog.Errorf("Fields with dataType %v is not supported in correlation fields list.", element.DataType)
			}
		}
	}
	return nil
}

// aggregateRecords aggregate the incomingRecord with existingRecord by updating
// stats and flow timestamps.
func (a *AggregationProcess) aggregateRecords(incomingRecord, existingRecord entities.Record, fillSrcStats, fillDstStats bool) error {
	if a.aggregateElements == nil {
		return nil
	}
	isLatest := false
	if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue("flowEndSeconds"); exist {
		if existingIeWithValue, _, exist2 := existingRecord.GetInfoElementWithValue("flowEndSeconds"); exist2 {
			incomingVal, err := ieWithValue.GetUnsigned32Value()
			if err != nil {
				return err
			}
			existingVal, err := existingIeWithValue.GetUnsigned32Value()
			if err != nil {
				return err
			}
			if incomingVal > existingVal {
				isLatest = true
				if err = existingIeWithValue.SetUnsigned32Value(incomingVal); err != nil {
					return err
				}
			}
		}
	}
	for _, element := range a.aggregateElements.NonStatsElements {
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(element)
			switch ieWithValue.GetInfoElement().Name {
			case "flowEndSeconds":
				// Flow end timestamp is already updated.
				break
			case "flowEndReason":
				// If the aggregated flow is set with flowEndReason as "EndOfFlowReason",
				// then we do not have to set again.
				existingVal, err := existingIeWithValue.GetUnsigned8Value()
				if err != nil {
					return err
				}
				incomingVal, err := ieWithValue.GetUnsigned8Value()
				if err != nil {
					return err
				}
				if existingVal != registry.EndOfFlowReason {
					if err = existingIeWithValue.SetUnsigned8Value(incomingVal); err != nil {
						return err
					}
				}
			case "tcpState":
				// Update tcpState when flow end timestamp is the latest
				if isLatest {
					incomingVal, err := ieWithValue.GetStringValue()
					if err != nil {
						return err
					}
					if err := existingIeWithValue.SetStringValue(incomingVal); err != nil {
						return err
					}
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
	isDelta := false
	for i, element := range statsElementList {
		isDelta = false
		if strings.Contains(element, "Delta") {
			isDelta = true
		}
		if ieWithValue, _, exist := incomingRecord.GetInfoElementWithValue(element); exist {
			existingIeWithValue, _, _ := existingRecord.GetInfoElementWithValue(element)
			incomingVal, err := ieWithValue.GetUnsigned64Value()
			if err != nil {
				return err
			}
			existingVal, err := existingIeWithValue.GetUnsigned64Value()
			if err != nil {
				return err
			}
			// Update the corresponding element in existing record.
			if !isDelta {
				if existingVal < incomingVal {
					if err = existingIeWithValue.SetUnsigned64Value(incomingVal); err != nil {
						return err
					}
				}
			} else {
				// We are simply adding the delta stats now. We expect delta stats to be
				// reset after sending the record from flowKeyMap in aggregation process.
				// Delta stats from source and destination nodes are added, so we will have
				// two times the stats approximately.
				// For delta stats, it is better to use source and destination specific
				// stats.
				if err = existingIeWithValue.SetUnsigned64Value(existingVal + incomingVal); err != nil {
					return err
				}
			}

			// Update the corresponding source element in antreaStatsElement list.
			if fillSrcStats {
				if existingIeWithValue, _, exist = existingRecord.GetInfoElementWithValue(antreaSourceStatsElements[i]); exist {
					if !isDelta {
						if err = existingIeWithValue.SetUnsigned64Value(incomingVal); err != nil {
							return err
						}
					} else {
						existingVal, err = existingIeWithValue.GetUnsigned64Value()
						if err != nil {
							return err
						}
						if err = existingIeWithValue.SetUnsigned64Value(incomingVal + existingVal); err != nil {
							return err
						}
					}
				} else {
					return fmt.Errorf("element does not exist in the record: %v", antreaSourceStatsElements[i])
				}
			}
			// Update the corresponding destination element in antreaStatsElement list.
			if fillDstStats {
				if existingIeWithValue, _, exist = existingRecord.GetInfoElementWithValue(antreaDestinationStatsElements[i]); exist {
					if !isDelta {
						if err = existingIeWithValue.SetUnsigned64Value(incomingVal); err != nil {
							return err
						}
					} else {
						existingVal, err = existingIeWithValue.GetUnsigned64Value()
						if err != nil {
							return err
						}
						if err = existingIeWithValue.SetUnsigned64Value(incomingVal + existingVal); err != nil {
							return err
						}
					}
				} else {
					return fmt.Errorf("element does not exist in the record: %v", antreaDestinationStatsElements[i])
				}
			}
		} else {
			return fmt.Errorf("element with name %v in statsElements not present in the incoming record", element)
		}
	}
	return nil
}

// ResetStatElementsInRecord is called by the user after the aggregation record
// is sent after its expiry either by active or inactive expiry interval. This should
// be called by user after acquiring the mutex in the Aggregation process.
func (a *AggregationProcess) ResetStatElementsInRecord(record entities.Record) error {
	statsElementList := a.aggregateElements.StatsElements
	antreaSourceStatsElements := a.aggregateElements.AggregatedSourceStatsElements
	antreaDestinationStatsElements := a.aggregateElements.AggregatedDestinationStatsElements
	for i, element := range statsElementList {
		if ieWithValue, _, exist := record.GetInfoElementWithValue(element); exist {
			ieWithValue.ResetValue()
		} else {
			return fmt.Errorf("element with name %v in statsElements is not present in the record", element)
		}
		if ieWithValue, _, exist := record.GetInfoElementWithValue(antreaSourceStatsElements[i]); exist {
			ieWithValue.ResetValue()
		} else {
			return fmt.Errorf("element with name %v in statsElements is not present in the record", antreaSourceStatsElements[i])
		}
		if ieWithValue, _, exist := record.GetInfoElementWithValue(antreaDestinationStatsElements[i]); exist {
			ieWithValue.ResetValue()
		} else {
			return fmt.Errorf("element with name %v in statsElements is not present in the record", antreaDestinationStatsElements[i])
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

	// Initialize the values of newly added stats info elements.
	for i, element := range statsElementList {
		if ieWithValue, _, exist := record.GetInfoElementWithValue(element); exist {
			// Initialize the corresponding source element in antreaStatsElement list.
			value := uint64(0)
			ie, err := registry.GetInfoElement(antreaSourceStatsElements[i], registry.AntreaEnterpriseID)
			if err != nil {
				return err
			}
			if fillSrcStats {
				value, err = ieWithValue.GetUnsigned64Value()
				if err != nil {
					return err
				}
			}
			if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
				return err
			}

			// Initialize the corresponding destination element in antreaStatsElement list.
			ie, err = registry.GetInfoElement(antreaDestinationStatsElements[i], registry.AntreaEnterpriseID)
			if err != nil {
				return err
			}
			value = uint64(0)
			if fillDstStats {
				value, err = ieWithValue.GetUnsigned64Value()
				if err != nil {
					return err
				}
			}
			if err = record.AddInfoElement(entities.NewUnsigned64InfoElement(ie, value)); err != nil {
				return err
			}
		}
	}
	return nil
}

// isRecordFromSrc returns true if record belongs to inter-node flow and from source node.
func isRecordFromSrc(record entities.Record) bool {
	if srcIEWithValue, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		srcPodVal, _ := srcIEWithValue.GetStringValue()
		if srcPodVal == "" {
			return false
		}
	} else {
		return false
	}
	if dstIEWithValue, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		dstPodVal, _ := dstIEWithValue.GetStringValue()
		if dstPodVal != "" {
			return false
		}
	}
	return true
}

// isRecordFromDst returns true if record belongs to inter-node flow and from destination node.
func isRecordFromDst(record entities.Record) bool {
	if dstIEWithValue, _, exist := record.GetInfoElementWithValue("destinationPodName"); exist {
		dstPodVal, _ := dstIEWithValue.GetStringValue()
		if dstPodVal == "" {
			return false
		}
	} else {
		return false
	}
	if srcIEWithValue, _, exist := record.GetInfoElementWithValue("sourcePodName"); exist {
		srcPodVal, _ := srcIEWithValue.GetStringValue()
		if srcPodVal != "" {
			return false
		}
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
func getFlowKeyFromRecord(record entities.Record) (*FlowKey, bool, error) {
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
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			port, err := element.GetUnsigned16Value()
			if err != nil {
				return nil, false, err
			}
			if name == "sourceTransportPort" {
				flowKey.SourcePort = port
			} else {
				flowKey.DestinationPort = port
			}
		case "sourceIPv4Address", "destinationIPv4Address":
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				break
			}
			addr, err := element.GetIPAddressValue()
			if err != nil {
				return nil, false, err
			}
			if strings.Contains(name, "source") {
				isSrcIPv4Filled = true
				flowKey.SourceAddress = addr.String()
			} else {
				isDstIPv4Filled = true
				flowKey.DestinationAddress = addr.String()
			}
		case "sourceIPv6Address", "destinationIPv6Address":
			element, _, exist := record.GetInfoElementWithValue(name)
			if (isSrcIPv4Filled && strings.Contains(name, "source")) || (isDstIPv4Filled && strings.Contains(name, "destination")) {
				if exist {
					klog.Warning("Two ip versions (IPv4 and IPv6) are not supported for flow key.")
				}
				break
			}
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			addr, err := element.GetIPAddressValue()
			if err != nil {
				return nil, false, err
			}
			if strings.Contains(name, "source") {
				flowKey.SourceAddress = addr.String()
			} else {
				flowKey.DestinationAddress = addr.String()
			}
		case "protocolIdentifier":
			element, _, exist := record.GetInfoElementWithValue(name)
			if !exist {
				return nil, false, fmt.Errorf("%s does not exist", name)
			}
			proto, err := element.GetUnsigned8Value()
			if err != nil {
				return nil, false, err
			}
			flowKey.Protocol = proto
		}
	}
	return flowKey, isSrcIPv4Filled && isDstIPv4Filled, nil
}

func validateDataRecord(record entities.Record) bool {
	return record.GetFieldCount() == uint16(len(record.GetOrderedElementList()))
}

// isCorrelationRequired returns true for InterNode flowType when
// either the egressNetworkPolicyRuleAction is not deny (drop/reject) or
// the ingressNetworkPolicyRuleAction is not reject.
func isCorrelationRequired(flowType uint8, record entities.Record) bool {
	if flowType == registry.FlowTypeInterNode {
		if egressRuleActionIe, _, exist := record.GetInfoElementWithValue("egressNetworkPolicyRuleAction"); exist {
			egressRuleAction, _ := egressRuleActionIe.GetUnsigned8Value()
			if egressRuleAction == registry.NetworkPolicyRuleActionDrop || egressRuleAction == registry.NetworkPolicyRuleActionReject {
				return false
			}
		}
		if ingressRuleActionIe, _, exist := record.GetInfoElementWithValue("ingressNetworkPolicyRuleAction"); exist {
			ingressRuleAction, _ := ingressRuleActionIe.GetUnsigned8Value()
			if ingressRuleAction == registry.NetworkPolicyRuleActionReject {
				return false
			}
		}
		return true
	}
	return false
}
