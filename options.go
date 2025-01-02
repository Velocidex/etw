//go:build windows
// +build windows

package etw

/*
	#include "windows.h"
*/
import "C"
import (
	"fmt"

	"golang.org/x/sys/windows"
)

// SessionOptions describes Session subscription options.
//
// Most of options will be passed to EnableTraceEx2 and could be refined in
// its docs: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
type SessionOptions struct {
	// Name specifies a name of ETW session being created. Further a session
	// could be controlled from other processed by it's name, so it should be
	// unique.
	Name string

	// Provider GUID to be added to this session.
	Guid windows.GUID

	// Level represents provider-defined value that specifies the level of
	// detail included in the event. Higher levels imply that you get lower
	// levels as well. For example, with TRACE_LEVEL_ERROR you'll get all
	// events except ones with level critical. Check `EventDescriptor.Level`
	// values for current event verbosity level.
	Level TraceLevel

	// MatchAnyKeyword is a bitmask of keywords that determine the category of
	// events that you want the provider to write. The provider writes the
	// event if any of the event's keyword bits match any of the bits set in
	// this mask.
	//
	// If MatchAnyKeyword is not set the session will receive ALL possible
	// events (which is equivalent setting all 64 bits to 1).
	//
	// Passed as is to EnableTraceEx2. Refer to its remarks for more info:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	MatchAnyKeyword uint64

	// MatchAllKeyword is an optional bitmask that further restricts the
	// category of events that you want the provider to write. If the event's
	// keyword meets the MatchAnyKeyword condition, the provider will write the
	// event only if all of the bits in this mask exist in the event's keyword.
	//
	// This mask is not used if MatchAnyKeyword is zero.
	//
	// Passed as is to EnableTraceEx2. Refer to its remarks for more info:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	MatchAllKeyword uint64

	// EnableProperties defines a set of provider properties consumer wants to
	// enable. Properties adds fields to ExtendedEventInfo or asks provider to
	// sent more events.
	//
	// For more info about available properties check EnableProperty doc and
	// original API reference:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
	EnableProperties []EnableProperty

	// Rundown is a boolean value to determine whether it will be a standard
	// ETW session, or whether the rundown parameter will be provided.
	CaptureState bool

	// Calling TdhGetEventMapInformation is very slow and causes
	// events to be dropped, yet for most fields it is not needed. We
	// turn this off by default to reduce endpoint load.
	EnableMapInfo bool
}

// Option is any function that modifies SessionOptions. Options will be called
// on default config in NewSession. Subsequent options that modifies same
// fields will override each other.
type Option func(cfg *SessionOptions)

// WithName specifies a provided @name for the creating session. Further that
// session could be controlled from other processed by it's name, so it should be
// unique.
func WithName(name string) Option {
	return func(cfg *SessionOptions) {
		cfg.Name = name
	}
}

// WithLevel specifies a maximum level consumer is interested in. Higher levels
// imply that you get lower levels as well. For example, with TRACE_LEVEL_ERROR
// you'll get all events except ones with level critical.
func WithLevel(lvl TraceLevel) Option {
	return func(cfg *SessionOptions) {
		cfg.Level = lvl
	}
}

// WithMatchKeywords allows to specify keywords of receiving events. Each event
// has a set of keywords associated with it. That keywords are encoded as bit
// masks and matched with provided @anyKeyword and @allKeyword values.
//
// A session will receive only those events whose keywords masks has ANY of
// @anyKeyword and ALL of @allKeyword bits sets.
//
// For more info take a look a SessionOptions docs. To query keywords defined
// by specific provider identified by <GUID> try:
//
//	logman query providers <GUID>
func WithMatchKeywords(anyKeyword, allKeyword uint64) Option {
	return func(cfg *SessionOptions) {
		cfg.MatchAnyKeyword = anyKeyword
		cfg.MatchAllKeyword = allKeyword
	}
}

// WithProperty enables additional provider feature toggled by @p. Subsequent
// WithProperty options will enable all provided options.
//
// For more info about available properties check EnableProperty doc and
// original API reference:
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
func WithProperty(p EnableProperty) Option {
	return func(cfg *SessionOptions) {
		cfg.EnableProperties = append(cfg.EnableProperties, p)
	}
}

// TraceLevel represents provider-defined value that specifies the level of
// detail included in the event. Higher levels imply that you get lower
// levels as well.
type TraceLevel C.UCHAR

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	TRACE_LEVEL_CRITICAL    = TraceLevel(1)
	TRACE_LEVEL_ERROR       = TraceLevel(2)
	TRACE_LEVEL_WARNING     = TraceLevel(3)
	TRACE_LEVEL_INFORMATION = TraceLevel(4)
	TRACE_LEVEL_VERBOSE     = TraceLevel(5)
)

// EnableProperty enables a property of a provider session is subscribing for.
//
// For more info about available properties check original API reference:
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
type EnableProperty C.ULONG

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	// Include in the ExtendedEventInfo the security identifier (SID) of the user.
	EVENT_ENABLE_PROPERTY_SID = EnableProperty(0x001)

	// Include in the ExtendedEventInfo the terminal session identifier.
	EVENT_ENABLE_PROPERTY_TS_ID = EnableProperty(0x002)

	// Include in the ExtendedEventInfo a call stack trace for events written
	// using EventWrite.
	EVENT_ENABLE_PROPERTY_STACK_TRACE = EnableProperty(0x004)

	// Filters out all events that do not have a non-zero keyword specified.
	// By default events with 0 keywords are accepted.
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 = EnableProperty(0x010)

	// Filters out all events that are either marked as an InPrivate event or
	// come from a process that is marked as InPrivate. InPrivate implies that
	// the event or process contains some data that would be considered private
	// or personal. It is up to the process or event to designate itself as
	// InPrivate for this to work.
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = EnableProperty(0x200)
)

// These options apply to the KernelTracer
type RundownOptions struct {
	Registry, Process, ImageLoad,
	Network, Driver, File, Thread, Handles bool

	// If set we install stack tracing for those events
	StackTracing *RundownOptions
}

// A convenience function to create a RundownOptions object from a
// list of the
func (self *RundownOptions) Set(trace_type string) error {
	switch trace_type {
	case "registry":
		self.Registry = true

	case "process":
		self.Process = true

	case "image_load":
		self.ImageLoad = true

	case "network":
		self.Network = true

	case "driver":
		self.Driver = true

	case "file":
		self.File = true

	case "thread":
		self.Thread = true

	case "handle":
		self.Handles = true

	default:
		return fmt.Errorf("Invalid event type %v", trace_type)
	}

	return nil
}
