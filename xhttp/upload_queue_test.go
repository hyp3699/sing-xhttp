package xhttp

import (
	"testing"
	"time"
)

func TestUploadQueueCloseUnblocksPush(t *testing.T) {
	queue := newUploadQueue(1)
	if err := queue.Push(packet{seq: 0, payload: []byte{1}}); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- queue.Push(packet{seq: 1, payload: []byte{2}})
	}()

	select {
	case <-result:
		t.Fatal("Push returned before the queue was closed")
	case <-time.After(20 * time.Millisecond):
	}

	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Push succeeded after queue close")
		}
	case <-time.After(time.Second):
		t.Fatal("Push remained blocked after queue close")
	}
}
