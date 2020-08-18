package collector

import (
	"bytes"
	"k8s.io/klog"
	"net"
)

func (cp *UDPCollectingProcess) start(address net.Addr, maxBufferSize uint16, workerNum int) {
	cp.initWorkers(workerNum)
	listener, err := net.ResolveUDPAddr(address.Network(), address.String())
	conn, err := net.ListenUDP("udp", listener)
	if err != nil {
		klog.Errorf("Cannot start collecting process on %s: %v", address.String(), err)
	}

	klog.Infof("Start %s collecting process on %s", address.Network(), address.String())
	for {
		buff := make([]byte, maxBufferSize)
		size, err := conn.Read(buff)
		if err != nil {
			klog.Errorf("Error in collecting process: %v", err)
			return
		}
		message := make([]byte, size)
		copy(message, buff[0:size])
		klog.Infof("Receiving %d bytes from %s", size, address.String())
		cp.processMessage(message)
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




