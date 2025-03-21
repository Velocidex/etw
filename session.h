// MinGW headers are always restricted to the lowest possible Windows version,
// so specify Win7+ manually.
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <winternl.h>

// OpenTraceHelper helps to access EVENT_TRACE_LOGFILEW union fields and pass
// pointer to C not warning CGO checker.
TRACEHANDLE OpenTraceHelper(LPWSTR name, UINT64 ctx);

// GetArraySize extracts a size of array located at property @i.
ULONG GetArraySize(PEVENT_RECORD event, PTRACE_EVENT_INFO info, int idx, UINT32* count);

// GetPropertyLength returns an associated length of the @j-th property of @pInfo.
// If the length is available, retrieve it here. In some cases, the length is 0.
// This can signify that we are dealing with a variable length field such as a structure
// or a string.
ULONG GetPropertyLength(PEVENT_RECORD event, PTRACE_EVENT_INFO info, int idx, UINT32* propertyLength);

///////////////////////////////////////////////////////////////////////////////////////////////
// All the function below is a helpers for go code to handle dynamic arrays and unnamed unions.
///////////////////////////////////////////////////////////////////////////////////////////////

// Helpers for event property parsing.
ULONGLONG GetPropertyName(PTRACE_EVENT_INFO info, int idx);
USHORT GetInType(PTRACE_EVENT_INFO info, int idx);
USHORT GetOutType(PTRACE_EVENT_INFO info, int idx);
LPWSTR GetMapName(PTRACE_EVENT_INFO info, int idx);
int GetStructStartIndex(PTRACE_EVENT_INFO info, int idx);
int GetStructLastIndex(PTRACE_EVENT_INFO info, int idx);
BOOL PropertyIsStruct(PTRACE_EVENT_INFO info, int idx);
BOOL PropertyIsArray(PTRACE_EVENT_INFO info, int idx);

// Event header unions getters.
LONGLONG GetTimeStamp(EVENT_HEADER header);
ULONG GetKernelTime(EVENT_HEADER header);
ULONG GetUserTime(EVENT_HEADER header);
ULONG64 GetProcessorTime(EVENT_HEADER header);

// Helpers for extended data parsing.
USHORT GetExtType(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
ULONGLONG GetDataPtr(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
USHORT GetDataSize(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int idx);
ULONG GetAddress32(PEVENT_EXTENDED_ITEM_STACK_TRACE32 trace32, int idx);
ULONGLONG GetAddress64(PEVENT_EXTENDED_ITEM_STACK_TRACE64 trace64, int idx);



NTSYSCALLAPI NTSTATUS NtQueryObject(
  HANDLE                   Handle,
  OBJECT_INFORMATION_CLASS ObjectInformationClass,
  PVOID                    ObjectInformation,
  ULONG                    ObjectInformationLength,
  PULONG                   ReturnLength
);

// This struct definition seems wrong in winternl.h
// https://doxygen.reactos.org/d7/d19/struct____OBJECT__TYPE__INFORMATION.html
typedef struct _MyOBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR Reserved;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} MyOBJECT_TYPE_INFORMATION, *PMyOBJECT_TYPE_INFORMATION;


#ifndef ENABLE_TRACE_PARAMETERS_VERSION_2
#define ENABLE_TRACE_PARAMETERS_VERSION_2 2
#endif
