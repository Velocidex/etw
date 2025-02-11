package etw

/*
	#include "session.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"golang.org/x/sys/windows"
)

const (
	TDH_OUTTYPE_NULL = uintptr(0)
)

var (
	InvalidField = errors.New("No Field")
)

// A property may be lazy in which case the caller can materialize it
// on demand.
type LazyProperty func() interface{}

// Use this function to fetch and materialize the LazyProperty from
// the EventProps.
func GetLazyProperty(e *Event, name string) (interface{}, bool) {
	event_props := e.Props()
	cb_any, pres := event_props.Get(name)
	if !pres {
		return nil, false
	}

	value := reflect.ValueOf(cb_any)
	if !value.IsValid() {
		return cb_any, true
	}

	if value.Type().Kind() == reflect.Ptr {
		value = value.Elem()
	}

	// Function must take no args
	if value.Type().NumIn() != 0 {
		return cb_any, true
	}

	res := value.Call([]reflect.Value{})
	if len(res) != 1 || !res[0].IsValid() {
		return cb_any, true
	}

	event_props.Update(name, res[0].Interface())
	return res, true
}

// propertyParser is used for parsing properties from raw EVENT_RECORD
// structure.
type propertyParserInterface interface {
	EventProperties() (*ordereddict.Dict, error)
	free()
}

type propertyParser struct {
	record  C.PEVENT_RECORD
	info    C.PTRACE_EVENT_INFO
	data    uintptr
	endData uintptr
	ptrSize uintptr

	// Resolving MapInfo is very expensive and it is not needed much
	// of the time. Provide this to optionally skip this step.
	resolveMapInfo bool
}

func newPropertyParser(r C.PEVENT_RECORD,
	resolveMapInfo bool) (propertyParserInterface, error) {

	info, err := getEventInformation(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get event information; %w", err)
	}
	ptrSize := unsafe.Sizeof(uint64(0))
	if r.EventHeader.Flags&C.EVENT_HEADER_FLAG_32_BIT_HEADER == C.EVENT_HEADER_FLAG_32_BIT_HEADER {
		ptrSize = unsafe.Sizeof(uint32(0))
	}
	return &propertyParser{
		record:         r,
		info:           info,
		ptrSize:        ptrSize,
		data:           uintptr(r.UserData),
		endData:        uintptr(r.UserData) + uintptr(r.UserDataLength),
		resolveMapInfo: resolveMapInfo,
	}, nil
}

// getEventInformation wraps TdhGetEventInformation. It extracts some kind of
// simplified event information used by Tdh* family of function.
//
// Returned info MUST be freed after use.
func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var (
		// Start off with a reasonable buffer size
		bufferSize C.ulong             = 1024 * 2
		pInfo      C.PTRACE_EVENT_INFO = C.PTRACE_EVENT_INFO(C.malloc(C.size_t(bufferSize)))
	)

	// Retrieve a buffer size if it is not enough.
	ret := C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {

		// Resize the buffer for the requires size.
		C.free(unsafe.Pointer(pInfo))

		pInfo = C.PTRACE_EVENT_INFO(C.malloc(C.size_t(bufferSize)))
		if pInfo == nil {
			return nil, fmt.Errorf("malloc(%v) failed", bufferSize)
		}

		// Fetch the buffer itself.
		ret = C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	}

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		C.free(unsafe.Pointer(pInfo))
		return nil, fmt.Errorf("TdhGetEventInformation failed; %w", status)
	}

	return pInfo, nil
}

// free frees associated PTRACE_EVENT_INFO if any assigned.
func (p *propertyParser) free() {
	if p.info != nil {
		C.free(unsafe.Pointer(p.info))
	}
	p.info = nil
}

// getPropertyName returns a name of the @i-th event property.
func (p *propertyParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	length := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(length))
}

// getPropertyValue retrieves a value of @i-th property.
//
// N.B. getPropertyValue HIGHLY depends not only on @i but also on memory
// offsets, so check twice calling with non-sequential indexes.
func (p *propertyParser) getPropertyValue(i int) (interface{}, error) {
	var arraySizeC C.uint
	ret := C.GetArraySize(p.record, p.info, C.int(i), &arraySizeC)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("failed to get array size; %w", status)
	}

	arraySize := int(arraySizeC)
	result := make([]interface{}, arraySize)
	for j := 0; j < arraySize; j++ {
		var (
			value interface{}
			err   error
		)
		// Note that we pass same idx to parse function. Actual returned values are controlled
		// by data pointers offsets.
		if int(C.PropertyIsStruct(p.info, C.int(i))) == 1 {
			value, err = p.parseStruct(i)
		} else {
			value, err = p.parseSimpleType(i)
		}

		if err == nil {
			result[j] = value
		}
	}

	if int(C.PropertyIsArray(p.info, C.int(i))) == 1 {
		return result, nil
	}
	return result[0], nil
}

// parseStruct tries to extract fields of embedded structure at property @i.
func (p *propertyParser) parseStruct(i int) (map[string]interface{}, error) {
	startIndex := int(C.GetStructStartIndex(p.info, C.int(i)))
	lastIndex := int(C.GetStructLastIndex(p.info, C.int(i)))

	structure := make(map[string]interface{}, lastIndex-startIndex)
	for j := startIndex; j < lastIndex; j++ {
		name := p.getPropertyName(j)
		value, err := p.getPropertyValue(j)
		if err != nil {
			return nil, fmt.Errorf("failed parse field %q of complex property type; %w", name, err)
		}
		structure[name] = value
	}
	return structure, nil
}

// For some weird reasons non of mingw versions has TdhFormatProperty defined
// so the only possible way is to use a DLL here.
//
//nolint:gochecknoglobals
var (
	tdh               = windows.NewLazySystemDLL("Tdh.dll")
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
)

// parseSimpleType wraps TdhFormatProperty to get rendered to string value of
// @i-th event property.
func (p *propertyParser) parseSimpleType(i int) (string, error) {
	var mapInfo unsafe.Pointer
	var err error

	// No more data available in this record
	availableData := p.endData - p.data
	if availableData == 0 {
		return "", InvalidField
	}

	// This function call is very expensive and can hold up the
	// processing loop causing many events to be dropped. We
	// optionally can disable looking up the map info completely. This
	// seems to work well for most providers.
	if p.resolveMapInfo {
		mapInfo, err = getMapInfo(p.record, p.info, i)
		if err != nil {
			return "", fmt.Errorf("failed to get map info; %w", err)
		}
	}

	var propertyLength C.uint
	ret := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to get property length; %w", status)
	}

	// Not enough data is available to parse this field.
	if availableData < uintptr(propertyLength) {
		return "", InvalidField
	}

	inType := uintptr(C.GetInType(p.info, C.int(i)))
	outType := uintptr(C.GetOutType(p.info, C.int(i)))
	if outType == TDH_OUTTYPE_NULL {
		outType = inType
	}

	// We are going to guess a value size to save a DLL call, so preallocate.
	var (
		userDataConsumed  C.int = 0
		formattedDataSize C.int = 50
	)
	formattedData := make([]byte, int(formattedDataSize))

retryLoop:
	for {
		r0, _, _ := tdhFormatProperty.Call(
			uintptr(unsafe.Pointer(p.record)),
			uintptr(mapInfo),
			p.ptrSize,
			inType,
			outType,
			uintptr(propertyLength),
			p.endData-p.data,
			p.data,
			uintptr(unsafe.Pointer(&formattedDataSize)),
			uintptr(unsafe.Pointer(&formattedData[0])),
			uintptr(unsafe.Pointer(&userDataConsumed)),
		)

		switch status := windows.Errno(r0); status {
		case windows.ERROR_SUCCESS:
			break retryLoop

		case windows.ERROR_INSUFFICIENT_BUFFER:
			formattedData = make([]byte, int(formattedDataSize))
			continue

		case windows.ERROR_EVT_INVALID_EVENT_DATA:
			// Can happen if the MapInfo doesn't match the actual data, e.g pure ETW provider
			// works with the outdated WEL manifest. Discarding MapInfo allows us to access
			// at least the non-interpreted data.
			if mapInfo != nil {
				mapInfo = nil
				continue
			}
			fallthrough // Can't fix. Error.

		default:
			return "", InvalidField
		}
	}
	p.data += uintptr(userDataConsumed)

	return createUTF16String(uintptr(unsafe.Pointer(&formattedData[0])), int(formattedDataSize)), nil
}

// getMapInfo retrieve the mapping between the @i-th field and the structure it represents.
// If that mapping exists, function extracts it and returns a pointer to the buffer with
// extracted info. If no mapping defined, function can legitimately return `nil, nil`.
func getMapInfo(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, i int) (unsafe.Pointer, error) {
	mapName := C.GetMapName(info, C.int(i))

	// Query map info if any exists.
	var mapSize C.ulong
	ret := C.TdhGetEventMapInformation(event, mapName, nil, &mapSize)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_NOT_FOUND:
		return nil, nil // Pretty ok, just no map info
	case windows.ERROR_INSUFFICIENT_BUFFER:
		// Info exists -- need a buffer.
	default:
		return nil, fmt.Errorf("TdhGetEventMapInformation failed to get size; %w", status)
	}

	// Get the info itself.
	mapInfo := make([]byte, int(mapSize))
	ret = C.TdhGetEventMapInformation(
		event,
		mapName,
		(C.PEVENT_MAP_INFO)(unsafe.Pointer(&mapInfo[0])),
		&mapSize)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("TdhGetEventMapInformation failed; %w", status)
	}

	if len(mapInfo) == 0 {
		return nil, nil
	}
	return unsafe.Pointer(&mapInfo[0]), nil
}

func windowsGUIDToGo(guid C.GUID) windows.GUID {
	var data4 [8]byte
	for i := range data4 {
		data4[i] = byte(guid.Data4[i])
	}
	return windows.GUID{
		Data1: uint32(guid.Data1),
		Data2: uint16(guid.Data2),
		Data3: uint16(guid.Data3),
		Data4: data4,
	}
}

// stampToTime translates FileTime to a golang time. Same as in standard packages.
func stampToTime(quadPart C.LONGLONG) time.Time {
	ft := windows.Filetime{
		HighDateTime: uint32(quadPart >> 32),
		LowDateTime:  uint32(quadPart & math.MaxUint32),
	}
	return time.Unix(0, ft.Nanoseconds())
}

// Creates UTF16 string from raw parts.
//
// Actually in go we have no way to make a slice from raw parts, ref:
// - https://github.com/golang/go/issues/13656
// - https://github.com/golang/go/issues/19367
// So the recommended way is "a fake cast" to the array with maximal len
// with a following slicing.
// Ref: https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
func createUTF16String(ptr uintptr, len int) string {
	// Race detector doesn't like this cast, but it's safe.
	// ptr is represented as a kernel address > 0xC0'0000'0000
	if !AllowKernelAccess && !inKernelSpace(ptr) {
		return ""
	}
	if len == 0 {
		return ""
	}
	bytes := (*[1 << 29]uint16)(unsafe.Pointer(ptr))[:len:len]
	return windows.UTF16ToString(bytes)
}

func (p *propertyParser) EventProperties() (*ordereddict.Dict, error) {
	properties := ordereddict.NewDict()

	for i := 0; i < int(p.info.TopLevelPropertyCount); i++ {
		name := p.getPropertyName(i)
		value, err := p.getPropertyValue(i)
		if err != nil {
			// Parsing values we consume given event data buffer with var length chunks.
			// If we skip any -- we'll lost offset, so fail early.
			return nil, fmt.Errorf("failed to parse %q value; %w", name, err)
		}
		properties.Set(name, value)
	}
	return properties, nil
}
