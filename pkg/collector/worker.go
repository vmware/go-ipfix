package collector

import (
	"bytes"
	"k8s.io/klog"
)

type Worker struct {
	id          uint16
	messageChan chan *bytes.Buffer
	errorChan   chan bool
	workerPool  chan chan *bytes.Buffer
	decodeFunc  func(message *bytes.Buffer) (*Packet, error)
}

func CreateWorker(id int, workerPool chan chan *bytes.Buffer, decodeFunc func(message *bytes.Buffer) (*Packet, error)) *Worker {
	return &Worker{
		id:          uint16(id),
		messageChan: make(chan *bytes.Buffer),
		errorChan:   make(chan bool),
		workerPool:  workerPool,
		decodeFunc:  decodeFunc,
	}
}

// start a goroutine to process the message
func (worker *Worker) start() {
	go func() {
		for {
			select {
			case <-worker.errorChan:
				break
			case worker.workerPool <- worker.messageChan:
				message := <-worker.messageChan
				packet, err := worker.decodeFunc(message)
				if err != nil {
					klog.Errorf("Error in decoding message: %v", err)
				}
				klog.Infoln(packet)
			}
		}
	}()
}

func (worker *Worker) stop() {
	worker.errorChan <- true
}
