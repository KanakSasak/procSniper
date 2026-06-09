package domain

import "context"

// EventProcessor is an interface for processing monitoring events.
// This allows the ETW consumer to work with any detection service implementation.
type EventProcessor interface {
	ProcessFileCreate(ctx context.Context, event *MonitorEvent)
	ProcessFileModified(ctx context.Context, event *MonitorEvent)
	ProcessFileDelete(ctx context.Context, event *MonitorEvent)
	ProcessProcessCreate(ctx context.Context, event *MonitorEvent)
	ProcessLSASSAccess(ctx context.Context, event *MonitorEvent)
}
