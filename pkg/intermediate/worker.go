package intermediate

import (
	"k8s.io/klog/v2"
)

type aggregationWorker interface {
	start()
	stop()
}

type worker[T any] struct {
	id        int
	inputChan <-chan T
	errChan   chan bool
	job       func(T) error
}

func createWorker[T any](id int, inputChan <-chan T, job func(T) error) *worker[T] {
	return &worker[T]{
		id,
		inputChan,
		make(chan bool),
		job,
	}
}

func (w *worker[T]) start() {
	go func() {
		for {
			select {
			case <-w.errChan:
				return
			case v, ok := <-w.inputChan:
				if !ok { // inputChan is closed and empty
					break
				}
				err := w.job(v)
				if err != nil {
					klog.ErrorS(err, "Failed to process IPFIX input")
				}
			}
		}
	}()
}

func (w *worker[T]) stop() {
	w.errChan <- true
}
