//go:build windows
// +build windows

package etw

/*
	#include "session.h"
*/
import "C"
import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"golang.org/x/sys/windows"
)

// Event is a single event record received from ETW provider. The only thing
// that is parsed implicitly is an EventHeader (which just translated from C
// structures mostly 1:1), all other data are parsed on-demand.
//
// Events will be passed to the user EventCallback. It's invalid to use Event
// methods outside of an EventCallback.
type Event struct {
	mu sync.Mutex

	Header EventHeader

	// Cached parsed fields. It is possible for an event callback to
	// mutate these fields to add/replace any field. This allows a
	// callback to enrich or correct any of the raw data parsed from
	// the ETW system.
	parsed      *ordereddict.Dict
	event_props *ordereddict.Dict
	header      *ordereddict.Dict

	// A Lazy function to resolve the backtrace if available.
	backtrace func() interface{}

	eventRecord C.PEVENT_RECORD
}

func (self *Event) Backtrace() interface{} {
	if self.backtrace != nil {
		return self.backtrace()
	}
	return []string{}
}

func (self *Event) MarshalJSON() ([]byte, error) {
	tmp := ordereddict.NewDict().
		Set("System", self.HeaderProps()).
		Set("EventData", self.Props())

	if self.backtrace != nil {
		tmp.Set("Backtrace", self.Backtrace())
	}

	return tmp.MarshalJSON()
}

// EventHeader contains an information that is common for every ETW event
// record.
//
// EventHeader fields is self-descriptive. If you need more info refer to the
// original struct docs:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	EventDescriptor

	ThreadID  uint32
	ProcessID uint32
	TimeStamp time.Time

	ProviderID windows.GUID
	ActivityID windows.GUID

	Flags         uint16
	KernelTime    uint32
	UserTime      uint32
	ProcessorTime uint64

	// For the kernel logger the actual event ID is encoded in the
	// OpCode and the provider GUID. We parse these to generate a
	// KernelLoggerType so we can act on it more efficiently.
	KernelLoggerType KernelLoggerType
}

// HasCPUTime returns true if the event has separate UserTime and KernelTime
// measurements. Otherwise the value of UserTime and KernelTime is meaningless
// and you should use ProcessorTime instead.
func (h EventHeader) HasCPUTime() bool {
	switch {
	case h.Flags&C.EVENT_HEADER_FLAG_NO_CPUTIME != 0:
		return false
	case h.Flags&C.EVENT_HEADER_FLAG_PRIVATE_SESSION != 0:
		return false
	default:
		return true
	}
}

// EventDescriptor contains low-level metadata that defines received event.
// Most of fields could be used to refine events filtration.
//
// For detailed information about fields values refer to EVENT_DESCRIPTOR docs:
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

// EventProperties returns a map that represents events-specific data provided
// by event producer. Returned data depends on the provider, event type and even
// provider and event versions.
//
// The simplest (and the recommended) way to parse event data is to use TDH
// family of functions that render event data to the strings exactly as you can
// see it in the Event Viewer.
//
// EventProperties returns a map that could be interpreted as "structure that
// fit inside a map". Map keys is a event data field names, map values is field
// values rendered to strings. So map values could be one of the following:
//   - `[]string` for arrays of any types;
//   - `map[string]interface{}` for fields that are structures;
//   - `string` for any other values.
//
// Take a look at `TestParsing` for possible EventProperties values.
func (e *Event) EventProperties(resolveMapInfo bool) (*ordereddict.Dict, error) {
	if e.eventRecord == nil {
		return nil, fmt.Errorf("usage of Event is invalid outside of EventCallback")
	}

	if e.eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		return ordereddict.NewDict().Set(
			"_", C.GoString((*C.char)(e.eventRecord.UserData))), nil
	}

	p, err := newPropertyParser(e.eventRecord, resolveMapInfo)
	if err != nil {
		// Cant parse the properties, just forward an empty set.
		return ordereddict.NewDict(), nil
	}
	defer p.free()

	return p.EventProperties()
}

func (self *Event) Parsed() *ordereddict.Dict {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.parsed != nil {
		return self.parsed
	}

	event := ordereddict.NewDict()
	self.header = ordereddict.NewDict().
		Set("ID", self.Header.ID).
		Set("ProcessID", self.Header.ProcessID).
		Set("TimeStamp", self.Header.TimeStamp).
		Set("Provider", self.Header.ProviderID.String()).
		Set("OpCode", self.Header.OpCode)
	event.Set("Header", self.header)

	if self.Header.KernelLoggerType != UnknownLoggerType {
		self.header.Set(
			"KernelEventType", self.Header.KernelLoggerType.String())
	}

	data, err := self.EventProperties(false)
	if err == nil {
		event.Set("EventProperties", data)
		self.event_props = data
	} else {
		self.event_props = ordereddict.NewDict()
	}

	self.parsed = event
	return event
}

func (self *Event) Props() *ordereddict.Dict {
	self.Parsed()

	self.mu.Lock()
	defer self.mu.Unlock()

	return self.event_props
}

func (self *Event) HeaderProps() *ordereddict.Dict {
	self.Parsed()

	self.mu.Lock()
	defer self.mu.Unlock()

	return self.header
}

// ExtendedEventInfo contains additional information about received event. All
// ExtendedEventInfo fields are optional and are nils being not set by provider.
//
// Presence of concrete fields is controlled by WithProperty option and an
// ability of event provider to set the required fields.
//
// More info about fields is available at EVENT_HEADER_EXTENDED_DATA_ITEM.ExtType
// documentation:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
type ExtendedEventInfo struct {
	SessionID    *uint32
	ActivityID   *windows.GUID
	UserSID      *windows.SID
	InstanceInfo *EventInstanceInfo
	StackTrace   *EventStackTrace
}

// EventInstanceInfo defines the relationship between events if its provided.
type EventInstanceInfo struct {
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
}

// EventStackTrace describes a call trace of the event occurred.
type EventStackTrace struct {
	MatchedID uint64
	Addresses []uint64
}

// ExtendedInfo extracts ExtendedEventInfo structure from native buffers of
// received event record.
//
// If no ExtendedEventInfo is available inside an event record function returns
// the structure with all fields set to nil.
func (e *Event) ExtendedInfo() ExtendedEventInfo {
	if e.eventRecord == nil { // Usage outside of event callback.
		return ExtendedEventInfo{}
	}
	if e.eventRecord.EventHeader.Flags&C.EVENT_HEADER_FLAG_EXTENDED_INFO == 0 {
		return ExtendedEventInfo{}
	}
	return e.parseExtendedInfo()
}

func (e *Event) parseExtendedInfo() ExtendedEventInfo {
	var extendedData ExtendedEventInfo
	for i := 0; i < int(e.eventRecord.ExtendedDataCount); i++ {
		dataPtr := unsafe.Pointer(uintptr(C.GetDataPtr(e.eventRecord.ExtendedData, C.int(i))))

		switch C.GetExtType(e.eventRecord.ExtendedData, C.int(i)) {
		case C.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
			cGUID := (C.LPGUID)(dataPtr)
			goGUID := windowsGUIDToGo(*cGUID)
			extendedData.ActivityID = &goGUID

		case C.EVENT_HEADER_EXT_TYPE_SID:
			cSID := (*C.SID)(dataPtr)
			goSID, err := (*windows.SID)(unsafe.Pointer(cSID)).Copy()
			if err == nil {
				extendedData.UserSID = goSID
			}

		case C.EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr)
			goSessionID := uint32(*cSessionID)
			extendedData.SessionID = &goSessionID

		case C.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr)
			extendedData.InstanceInfo = &EventInstanceInfo{
				InstanceID:       uint32(instanceInfo.InstanceId),
				ParentInstanceID: uint32(instanceInfo.ParentInstanceId),
				ParentGUID:       windowsGUIDToGo(instanceInfo.ParentGuid),
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			stack32 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE32)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress32(stack32, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack32.MatchId),
				Addresses: address,
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
			stack64 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE64)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG64(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress64(stack64, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack64.MatchId),
				Addresses: address,
			}

			// TODO:
			// EVENT_HEADER_EXT_TYPE_PEBS_INDEX, EVENT_HEADER_EXT_TYPE_PMC_COUNTERS
			// EVENT_HEADER_EXT_TYPE_PSM_KEY, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
			// EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
			// EVENT_HEADER_EXT_TYPE_PROV_TRAITS
		}
	}
	return extendedData
}
