package intermediate

import (
	"k8s.io/klog"

	"github.com/vmware/go-ipfix/pkg/entities"
)

type worker struct {
	id          int
	workerPool  chan chan *entities.Message
	messageChan chan *entities.Message
	errChan     chan bool
	job         func(*entities.Message) error
}

func createWorker(id int, wp chan chan *entities.Message, job func(*entities.Message) error) *worker {
	return &worker{
		id,
		wp,
		make(chan *entities.Message),
		make(chan bool),
		job,
	}
}

func (w *worker) start() {
	go func() {
		for {
			select {
			case <-w.errChan:
				break
			case w.workerPool <- w.messageChan:
				message := <-w.messageChan
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
