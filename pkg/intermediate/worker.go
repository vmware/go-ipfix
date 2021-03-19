package intermediate

import (
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
)

type worker struct {
	id          int
	messageChan chan *entities.Message
	errChan     chan bool
	job         func(*entities.Message) error
}

func createWorker(id int, messageChan chan *entities.Message, job func(*entities.Message) error) *worker {
	return &worker{
		id,
		messageChan,
		make(chan bool),
		job,
	}
}

func (w *worker) start() {
	go func() {
		for {
			select {
			case <-w.errChan:
				return
			case message, ok := <-w.messageChan:
				if !ok { // messageChan is closed and empty
					break
				}
				err := w.job(message)
				if err != nil {
					klog.Error(err)
				}
				klog.V(4).Info(message)
			}
		}
	}()
}

func (w *worker) stop() {
	w.errChan <- true
}
