//go:build windows && cgo
// +build windows,cgo

package etw

/*
	#cgo LDFLAGS: -ltdh

	#include "session.h"
*/
import "C"

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	EVENT_TRACE_FLAG_HANDLE = 0x80000040

	// KernelTraceControlGUID is the GUID for the kernel system logger
	KernelTraceControlGUID = windows.GUID{Data1: 0x9e814aad, Data2: 0x3204, Data3: 0x11d2,
		Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}}
	KernelTraceControlGUIDString = KernelTraceControlGUID.String()

	NetworkTraceGUID = windows.GUID{
		Data1: 0x9A280AC0,
		Data2: 0xC8E0,
		Data3: 0x11D1,
		Data4: [8]byte{0x84, 0xE2, 0x00, 0xC0, 0x4F, 0xB9, 0x98, 0xA2}}

	ProcessTraceGUID = windows.GUID{
		Data1: 0x3D6FA8D0,
		Data2: 0xFE05,
		Data3: 0x11D0,
		Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}

	FileTraceGUID = windows.GUID{
		Data1: 0x90CBDC39,
		Data2: 0x4A3E,
		Data3: 0x11D1,
		Data4: [8]byte{0x84, 0xF4, 0x00, 0x00, 0xF8, 0x04, 0x64, 0xE3}}

	RegistryTraceGUID = windows.GUID{
		Data1: 0xAE53722E,
		Data2: 0xC863,
		Data3: 0x11D2,
		Data4: [8]byte{0x86, 0x59, 0x00, 0xC0, 0x4F, 0xA3, 0x21, 0xA1}}

	// The kernel tracer's session name must be fixed.
	KernelTraceSessionName = C.KERNEL_LOGGER_NAMEA
)

// Provide a new session for KernelTraceControlGUID rundown
func NewKernelTraceSession(opts RundownOptions, cb EventCallback) (*Session, error) {
	self := &Session{
		name:      KernelTraceSessionName,
		providers: make(map[string]windows.GUID),
		callback: func(e *Event) {
			t := GetKernelEventType(e)
			e.Header.KernelLoggerType = t

			// Preprocess by the info manager
			e = KernelInfo.processEvent(e)
			if e != nil {
				cb(e)
			}
		},
	}

	utf16Name, err := windows.UTF16FromString(KernelTraceSessionName)
	if err != nil {
		return nil, fmt.Errorf("incorrect session name; %w", err) // unlikely
	}
	self.etwSessionName = utf16Name

	sessionNameSize := len(utf16Name) * 2
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameSize
	propertiesBuf := make([]byte, bufSize)
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)
	pProperties.Wnode.ClientContext = 1 // QPC for event Timestamp
	pProperties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID

	pProperties.Wnode.Guid.Data1 = C.ULONG(KernelTraceControlGUID.Data1)
	pProperties.Wnode.Guid.Data2 = C.USHORT(KernelTraceControlGUID.Data2)
	pProperties.Wnode.Guid.Data3 = C.USHORT(KernelTraceControlGUID.Data3)
	for i := 0; i < len(KernelTraceControlGUID.Data4); i++ {
		pProperties.Wnode.Guid.Data4[i] = C.UCHAR(KernelTraceControlGUID.Data4[i])
	}

	pProperties.EnableFlags = C.ULONG(getTraceFlags(opts))

	// Mark that we are going to process events in real time using a
	// callback.
	pProperties.LogFileMode = C.EVENT_TRACE_REAL_TIME_MODE

	ret := C.StartTraceW(
		&self.hSession,
		C.LPWSTR(unsafe.Pointer(&self.etwSessionName[0])),
		pProperties,
	)

	switch err := windows.Errno(ret); err {
	case windows.ERROR_ALREADY_EXISTS:
		return nil, ExistsError{SessionName: self.name}
	case windows.ERROR_SUCCESS:
		self.propertiesBuf = propertiesBuf

		flags := make([]uint32, 8)

		// To trigger rundown we need to first call
		// TraceSetInformation with no flags and then again with the
		// correct flags.
		ret := C.TraceSetInformation(self.hSession, C.TraceSystemTraceEnableFlagsInfo,
			C.PVOID(unsafe.Pointer(&flags[0])), C.ULONG(4*len(flags)))
		err = windows.Errno(ret)
		if err != windows.ERROR_SUCCESS {
			return nil, err
		}

		flags[0] = getTraceFlags(opts)

		if opts.Handles {
			flags[4] = uint32(EVENT_TRACE_FLAG_HANDLE)
		}

		ret = C.TraceSetInformation(self.hSession, C.TraceSystemTraceEnableFlagsInfo,
			C.PVOID(unsafe.Pointer(&flags[0])), C.ULONG(4*len(flags)))
		err := windows.Errno(ret)
		if err != windows.ERROR_SUCCESS {
			return nil, err
		}

		if opts.StackTracing != nil {
			err := installStackTraces(self, opts.StackTracing)
			if err != windows.ERROR_SUCCESS {
				return nil, err
			}
		}

		return self, nil
	default:
		return nil, fmt.Errorf("StartTraceW failed; %w", err)
	}
}

func installStackTraces(session *Session, opts *RundownOptions) error {
	events := make([]C.CLASSIC_EVENT_ID, 0)
	if opts.Process {
		setClassicEvent(&events, &ProcessTraceGUID, 1)
		setClassicEvent(&events, &ProcessTraceGUID, 2)
	}

	if opts.File {
		// CreateFile
		setClassicEvent(&events, &FileTraceGUID, 64)
		// DeleteFile
		setClassicEvent(&events, &FileTraceGUID, 70)
		// RenameFile
		setClassicEvent(&events, &FileTraceGUID, 71)
	}

	if opts.Registry {
		// RegCreateKey
		setClassicEvent(&events, &RegistryTraceGUID, 10)
		// RegOpenKey
		setClassicEvent(&events, &RegistryTraceGUID, 11)
		// RegSetValue
		setClassicEvent(&events, &RegistryTraceGUID, 14)
		// RegDeleteValue
		setClassicEvent(&events, &RegistryTraceGUID, 16)
	}

	// Many of these are not useful to stack trace because they happen
	// in the kernel itself.
	if opts.Network {
		setClassicEvent(&events, &NetworkTraceGUID, 12)
		setClassicEvent(&events, &NetworkTraceGUID, 28)
	}

	ret := C.TraceSetInformation(session.hSession, C.TraceStackTracingInfo,
		C.PVOID(unsafe.Pointer(&events[0])), C.ULONG(int(unsafe.Sizeof(events[0]))*len(events)))
	return windows.Errno(ret)
}

func setClassicEvent(events *[]C.CLASSIC_EVENT_ID,
	guid *windows.GUID, t KernelLoggerType) {

	in := C.CLASSIC_EVENT_ID{}
	in.EventGuid.Data1 = C.ULONG(guid.Data1)
	in.EventGuid.Data2 = C.USHORT(guid.Data2)
	in.EventGuid.Data3 = C.USHORT(guid.Data3)
	for i := 0; i < 8; i++ {
		in.EventGuid.Data4[i] = C.UCHAR(guid.Data4[i])
	}
	in.Type = C.UCHAR(t)

	*events = append(*events, in)
}

func getTraceFlags(opts RundownOptions) uint32 {
	res := uint32(C.EVENT_TRACE_FLAG_NO_SYSCONFIG)

	if opts.Registry {
		res |= C.EVENT_TRACE_FLAG_REGISTRY
	}

	if opts.Process {
		res |= C.EVENT_TRACE_FLAG_PROCESS
	}

	if opts.ImageLoad {
		res |= C.EVENT_TRACE_FLAG_IMAGE_LOAD
	}

	if opts.Network {
		res |= C.EVENT_TRACE_FLAG_NETWORK_TCPIP
	}

	if opts.Driver {
		res |= C.EVENT_TRACE_FLAG_DRIVER
	}

	if opts.File {
		res |= C.EVENT_TRACE_FLAG_FILE_IO |
			C.EVENT_TRACE_FLAG_FILE_IO_INIT |
			C.EVENT_TRACE_FLAG_DISK_FILE_IO
	}

	if opts.Thread {
		res |= C.EVENT_TRACE_FLAG_THREAD
	}

	return res
}
