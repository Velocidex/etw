//go:build windows && cgo

package etw

type KernelLoggerType int

// The events returned from the Kernel Logger
const (
	UnknownLoggerType KernelLoggerType = iota
	ProcessRundown
	CreateProcess
	TerminateProcess
	OpenThread
	SetThreadContext
	CreateHandle
	CloseHandle
	DuplicateHandle
	LoadImage
	UnloadImage
	ImageRundown
	RegOpenKey
	RegCloseKey
	RegCreateKCB
	RegDeleteKCB
	RegKCBRundown
	RegCreateKey
	RegDeleteKey
	RegDeleteValue
	RegQueryKey
	RegQueryValue
	RegSetValue
	FileOpEnd
	FileRundown
	ReleaseFile
	CloseFile
	DeleteFile
	RenameFile
	SetFileInformation
	ReadFile
	WriteFile
	EnumDirectory
	MapViewFile
	UnmapViewFile
	MapFileRundown
	SendTCPv4
	SendUDPv4
	RecvTCPv4
	RecvUDPv4
	DisconnectTCPv4
	RetransmitTCPv4
	ReconnectTCPv4
	ConnectTCPv4
	AcceptTCPv4
	SendTCPv6
	SendUDPv6
	RecvTCPv6
	RecvUDPv6
	DisconnectTCPv6
	RetransmitTCPv6
	ReconnectTCPv6
	ConnectTCPv6
	AcceptTCPv6
	VirtualAlloc
	VirtualFree
	QueryDNS
	ReplyDNS
	CreateThread
	TerminateThread
	ThreadRundown
	CreateFile
	StackWalk
)

func (self KernelLoggerType) String() string {
	switch self {
	case ProcessRundown:
		return "ProcessRundown"
	case CreateProcess:
		return "CreateProcess"
	case TerminateProcess:
		return "TerminateProcess"
	case OpenThread:
		return "OpenThread"
	case SetThreadContext:
		return "SetThreadContext"
	case CreateHandle:
		return "CreateHandle"
	case CloseHandle:
		return "CloseHandle"
	case DuplicateHandle:
		return "DuplicateHandle"
	case LoadImage:
		return "LoadImage"
	case UnloadImage:
		return "UnloadImage"
	case ImageRundown:
		return "ImageRundown"
	case RegOpenKey:
		return "RegOpenKey"
	case RegCloseKey:
		return "RegCloseKey"
	case RegCreateKCB:
		return "RegCreateKCB"
	case RegDeleteKCB:
		return "RegDeleteKCB"
	case RegKCBRundown:
		return "RegKCBRundown"
	case RegCreateKey:
		return "RegCreateKey"
	case RegDeleteKey:
		return "RegDeleteKey"
	case RegDeleteValue:
		return "RegDeleteValue"
	case RegQueryKey:
		return "RegQueryKey"
	case RegQueryValue:
		return "RegQueryValue"
	case RegSetValue:
		return "RegSetValue"
	case FileOpEnd:
		return "FileOpEnd"
	case FileRundown:
		return "FileRundown"
	case ReleaseFile:
		return "ReleaseFile"
	case CloseFile:
		return "CloseFile"
	case DeleteFile:
		return "DeleteFile"
	case RenameFile:
		return "RenameFile"
	case SetFileInformation:
		return "SetFileInformation"
	case ReadFile:
		return "ReadFile"
	case WriteFile:
		return "WriteFile"
	case EnumDirectory:
		return "EnumDirectory"
	case MapViewFile:
		return "MapViewFile"
	case UnmapViewFile:
		return "UnmapViewFile"
	case MapFileRundown:
		return "MapFileRundown"
	case SendTCPv4:
		return "SendTCPv4"
	case SendUDPv4:
		return "SendUDPv4"
	case RecvTCPv4:
		return "RecvTCPv4"
	case RecvUDPv4:
		return "RecvUDPv4"
	case DisconnectTCPv4:
		return "DisconnectTCPv4"
	case RetransmitTCPv4:
		return "RetransmitTCPv4"
	case ReconnectTCPv4:
		return "ReconnectTCPv4"
	case ConnectTCPv4:
		return "ConnectTCPv4"
	case AcceptTCPv4:
		return "AcceptTCPv4"
	case SendTCPv6:
		return "SendTCPv6"
	case SendUDPv6:
		return "SendUDPv6"
	case RecvTCPv6:
		return "RecvTCPv6"
	case RecvUDPv6:
		return "RecvUDPv6"
	case DisconnectTCPv6:
		return "DisconnectTCPv6"
	case RetransmitTCPv6:
		return "RetransmitTCPv6"
	case ReconnectTCPv6:
		return "ReconnectTCPv6"
	case ConnectTCPv6:
		return "ConnectTCPv6"
	case AcceptTCPv6:
		return "AcceptTCPv6"
	case VirtualAlloc:
		return "VirtualAlloc"
	case VirtualFree:
		return "VirtualFree"
	case QueryDNS:
		return "QueryDNS"
	case ReplyDNS:
		return "ReplyDNS"
	case CreateThread:
		return "CreateThread"
	case TerminateThread:
		return "TerminateThread"
	case ThreadRundown:
		return "ThreadRundown"
	case CreateFile:
		return "CreateFile"
	case StackWalk:
		return "StackWalk"

	default:
		return ""
	}
}

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntwmi/wmi_trace_packet/hookid.htm
func GetKernelEventType(e *Event) KernelLoggerType {
	switch e.Header.ProviderID.Data1 {

	// Process Information
	// {3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C}
	case 0x3d6fa8d0:
		switch e.Header.OpCode {
		case 1:
			return CreateProcess
		case 2:
			return TerminateProcess
		case 3:
			return ProcessRundown
		}

	// Thread Information
	// {3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C}
	case 0x3d6fa8d1:
		switch e.Header.OpCode {
		case 1:
			return CreateThread
		case 2:
			return TerminateThread
		case 3:
			return ThreadRundown
		}

	// Image loading/unloading
	// {2CB15D1D-5FC1-11D2-ABE1-00A0C911F518}
	case 0x2cb15d1d:
		switch e.Header.OpCode {
		case 2:
			return UnloadImage
		case 3:
			return ImageRundown
		case 10:
			return LoadImage
		}

	// TCP Network
	// {9A280AC0-C8E0-11D1-84E2-00C04FB998A2}
	case 0x9a280ac0:
		switch e.Header.OpCode {
		case 15:
			return AcceptTCPv4
		case 31:
			return AcceptTCPv6
		case 10:
			return SendTCPv4
		case 26:
			return SendTCPv6
		case 11:
			return RecvTCPv4
		case 27:
			return RecvTCPv6
		case 12:
			return ConnectTCPv4
		case 28:
			return ConnectTCPv6
		case 13:
			return DisconnectTCPv4
		case 29:
			return DisconnectTCPv6
		case 16:
			return ReconnectTCPv4
		case 32:
			return ReconnectTCPv6
		case 14:
			return RetransmitTCPv4
		case 30:
			return RetransmitTCPv6
		}

	// UDP Network
	// {BF3A50C5-A9C9-4988-A005-2DF0B7C80F80}
	case 0xbf3a50c5:
		switch e.Header.OpCode {
		case 10:
			return SendUDPv4
		case 26:
			return SendUDPv6
		case 11:
			return RecvUDPv4
		case 27:
			return RecvUDPv6
		}

	// Handles
	// {89497F50-EFFE-4440-8CF2-CE6B1CDCACA7}
	case 0x89497f50:
		switch e.Header.OpCode {
		case 32:
			return CreateHandle
		case 33:
			return CloseHandle
		case 34:
			return DuplicateHandle
		}

	// Registry Information
	// {AE53722E-C863-11D2-8659-00C04FA321A1}
	case 0xae53722e:
		switch e.Header.OpCode {
		case 10:
			return RegCreateKey
		case 11:
			return RegOpenKey
		case 27:
			return RegCloseKey
		case 12:
			return RegDeleteKey
		case 13:
			return RegQueryKey
		case 14:
			return RegSetValue
		case 15:
			return RegDeleteValue
		case 16:
			return RegQueryValue
		case 22:
			return RegCreateKCB
		case 23:
			return RegDeleteKCB
		case 25:
			return RegKCBRundown
		}

	// File activity.
	// {90CBDC39-4A3E-11D1-84F4-0000F80464E3}
	case 0x90cbdc39:
		switch e.Header.OpCode {
		case 37:
			return MapViewFile
		case 38:
			return UnmapViewFile
		case 39:
			return MapFileRundown
		case 36, 35, 32:
			return FileRundown
		case 64:
			return CreateFile
		case 65:
			return ReleaseFile
		case 66:
			return CloseFile
		case 67:
			return ReadFile
		case 68:
			return WriteFile
		case 69:
			return SetFileInformation
		case 70:
			return DeleteFile
		case 71:
			return RenameFile
		case 72:
			return EnumDirectory
		case 76:
			return FileOpEnd
		}

		// Stack traces
		// {DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3}
	case 0xdef2fe46:
		return StackWalk
	}

	return UnknownLoggerType
}
