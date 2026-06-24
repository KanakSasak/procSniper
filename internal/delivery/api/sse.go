//go:build windows

package api

import (
	"encoding/json"
	"net/http"
	"sync"
)

// sseEvent is one server-sent event: a named event with a pre-marshaled JSON payload.
type sseEvent struct {
	name string
	data []byte
}

// sseHub fans events out to all connected SSE clients. Sends are lossy per-client (a full client
// buffer drops that event for that client) so a slow browser never blocks the detection producers —
// the same backpressure stance as the alert/log channels.
type sseHub struct {
	mu      sync.RWMutex
	clients map[chan sseEvent]struct{}
	closed  bool
}

func newSSEHub() *sseHub {
	return &sseHub{clients: make(map[chan sseEvent]struct{})}
}

func (h *sseHub) subscribe() chan sseEvent {
	ch := make(chan sseEvent, 64)
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		close(ch) // hub is shutting down — hand back an already-closed channel so serveStream exits
		return ch
	}
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// Close disconnects every client and refuses new subscribers (used on server shutdown so SSE
// handlers return and http.Shutdown can complete).
func (h *sseHub) Close() {
	h.mu.Lock()
	for ch := range h.clients {
		delete(h.clients, ch)
		close(ch)
	}
	h.closed = true
	h.mu.Unlock()
}

func (h *sseHub) unsubscribe(ch chan sseEvent) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		delete(h.clients, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// broadcast marshals data once and offers it to every client (non-blocking).
func (h *sseHub) broadcast(event string, data interface{}) {
	payload, err := json.Marshal(data)
	if err != nil {
		return
	}
	ev := sseEvent{name: event, data: payload}
	h.mu.RLock()
	for ch := range h.clients {
		select {
		case ch <- ev:
		default: // slow client — drop this event for them
		}
	}
	h.mu.RUnlock()
}

// serveStream streams events to one client until it disconnects.
func (h *sseHub) serveStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.subscribe()
	defer h.unsubscribe(ch)

	// Open the stream so EventSource fires onopen.
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write([]byte("event: " + ev.name + "\ndata: "))
			_, _ = w.Write(ev.data)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}
}
