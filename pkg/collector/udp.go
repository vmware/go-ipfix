package collector

import (
	"bytes"
	"k8s.io/klog"
	"net"
)

func (cp *UDPCollectingProcess) Start() {
	cp.initWorkers(cp.workerNum)
	listener, err := net.ResolveUDPAddr(cp.address.Network(), cp.address.String())
	conn, err := net.ListenUDP("udp", listener)
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", cp.address.String(), err)
	}

	klog.Infof("Start %s collecting process on %s", cp.address.Network(), cp.address.String())
	for {
		select {
		case <-cp.stopChan:
			cp.stopWorkers()
			return
		default:
			buff := make([]byte, cp.maxBufferSize)
			size, err := conn.Read(buff)
			if err != nil {
				klog.Errorf("Error in collecting process: %v", err)
				return
			}
			message := make([]byte, size)
			copy(message, buff[0:size])
			klog.Infof("Receiving %d bytes from %s", size, cp.address.String())
			cp.processMessage(message)
		}
	}
}

// Initialize and start all workers
func (cp *UDPCollectingProcess) initWorkers(workerNum int) {
	for i := 0; i < workerNum; i++ {
		worker := CreateWorker(i, cp.workerPool, cp.DecodeMessage)
		cp.workerList[i] = worker
	}
	for _, worker := range cp.workerList {
		worker.start()
	}
}

// Stop all workers
func (cp *UDPCollectingProcess) stopWorkers() {
	for _, worker := range cp.workerList {
		worker.stop()
	}
}

// Send message to worker pool
func (cp *UDPCollectingProcess) processMessage(message []byte) {
	messageChan := <-cp.workerPool
	messageChan <- bytes.NewBuffer(message)
}

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
				return
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




