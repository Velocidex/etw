package etw

/*

   #include <session.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/ttlcache/v2"
	"golang.org/x/sys/windows"
)

var (
	KernelInfo = NewKernelInfoManager()
)

type Process struct {
	PID int

	Mappings []*Mapping
}

func (self *Process) AddMapping(mapping *Mapping) {
	self.Mappings = append(self.Mappings, mapping)
}

func (self *Process) GetMapping(addr uint64) (*Mapping, bool) {
	for _, m := range self.Mappings {
		if m.BaseAddr < addr && addr < m.EndAddr {
			return m, true
		}
	}
	return nil, false
}

type Handle struct {
	PID uint32

	// Object is the kernel address for the relevant object
	Object, Handle, Name, Type string
}

// A global manager that maintains information about the kernel. Can
// be queried by other ETW processors.
type KernelInfoManager struct {
	mu sync.Mutex

	// Does not change for the life of the program.
	typeNames map[string]string

	// Key = Object -> Value is full key name
	keysCache *ttlcache.Cache // map[string]string

	processInfos *ttlcache.Cache // map[uint64]*Process

	// A lookup from kernel device names to drive letters.
	deviceLookup map[string]string

	// A cache of known PE Symbols. Key is PE path
	peCache *ttlcache.Cache // map[string]*PESymbols

	previousEvent *Event

	fileCache *ttlcache.Cache //map[string]string
}

func (self *KernelInfoManager) Close() {
	self.keysCache.Close()
	self.processInfos.Close()
	self.peCache.Close()
	self.fileCache.Close()
}

func (self *KernelInfoManager) GetType(typeId string) string {
	name, ok := self.typeNames[typeId]
	if ok {
		return name
	}

	return ""
}

func (self *KernelInfoManager) NormalizeFilename(filename string) string {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self.normalizeFilename(filename)
}

func (self *KernelInfoManager) normalizeFilename(filename string) string {
	for deviceName, driveLetter := range self.deviceLookup {
		if strings.HasPrefix(filename, deviceName) {
			return driveLetter + filename[len(deviceName):]
		}
	}
	return filename
}

func (self *KernelInfoManager) GetFileCache(file_object string) (string, bool) {
	res, err := self.fileCache.Get(file_object)
	if err != nil {
		return "", false
	}

	return res.(string), true
}

func (self *KernelInfoManager) SetFileCache(file_object string, filename string) {
	self.fileCache.Set(file_object, filename)
}

func (self *KernelInfoManager) GetPEInfo(name string) (*PESymbols, bool) {
	res, err := self.peCache.Get(name)
	if err != nil {
		return nil, false
	}

	return res.(*PESymbols), true
}

func (self *KernelInfoManager) GetProcessInfo(pid string) (*Process, bool) {
	res, err := self.processInfos.Get(pid)
	if err != nil || res == nil {
		return nil, false
	}

	return res.(*Process), true
}

func (self *KernelInfoManager) DecorateStackTraces(e *Event) func() interface{} {
	event_props := e.Props()
	StackProcess, _ := event_props.GetString("StackProcess")
	pid, err := strconv.ParseUint(StackProcess, 0, 64)
	if err != nil {
		return nil
	}

	kernel_process, pres := self.GetProcessInfo("0")
	if !pres {
		return nil
	}

	PidStr := strconv.FormatUint(pid, 10)
	process, pres := self.GetProcessInfo(PidStr)
	if !pres {
		return nil
	}

	return func() interface{} {
		var tb []string

		for _, k := range event_props.Keys() {
			if !strings.HasPrefix(k, "Stack") {
				continue
			}

			v, pres := event_props.GetString(k)
			if !pres {
				continue
			}

			addr, err := strconv.ParseUint(v, 0, 64)
			if err != nil {
				continue
			}

			event_props.Update("StackProcess", addr)

			var mapping *Mapping

			// Kernel space
			if addr > 0x800000000000 {
				if kernel_process == nil {
					continue
				}

				mapping, pres = kernel_process.GetMapping(addr)
			} else {

				// Userspace
				mapping, pres = process.GetMapping(addr)
			}

			if !pres {
				continue
			}

			// Try to find the function name closest to the address
			rva := int64(addr - mapping.BaseAddr)
			func_name := self.GuessFunctionName(mapping.Filename, rva)

			if func_name != "" {
				tb = append(tb, fmt.Sprintf("%v!%v", mapping.dll, func_name))
			} else {
				// We dont have a func_name so just write the address in
				// the mapped dll.
				tb = append(tb, fmt.Sprintf("%v!%#x", mapping.dll, rva))
			}
		}
		return tb
	}
}

func (self *KernelInfoManager) GuessFunctionName(
	pe_path string, rva int64) string {

	symbols, err := self.peCache.Get(pe_path)
	if err != nil {
		var err error

		symbols, err = self.openPE(pe_path)
		if err != nil || symbols == nil {
			// Negative cache this so we dont try to keep opening the
			// same missing file. This can happen for example if the
			// file is on a remote share and we cant open it as
			// SYSTEM.
			symbols = &PESymbols{}
		}

		self.peCache.Set(pe_path, symbols)
	}

	return symbols.(*PESymbols).getFuncName(rva)
}

func (self *KernelInfoManager) processEvent(e *Event) (ret *Event) {

	// Hold onto the event in case the next event is a stack trace, so
	// we re-emit this event with the previous
	defer func() {
		if ret != nil {
			self.previousEvent = ret
		}
	}()

	switch e.Header.KernelLoggerType {

	case ImageRundown:
		mapping, err := self.NewMapping(e.Props())
		if err != nil {
			return e
		}

		PidStr := strconv.FormatUint(mapping.Pid, 10)

		proc, err := self.processInfos.Get(PidStr)
		if err != nil {
			proc = &Process{PID: int(mapping.Pid)}
			self.processInfos.Set(PidStr, proc)
		}

		proc.(*Process).AddMapping(mapping)

	case ReadFile, WriteFile, ReleaseFile, CloseFile:
		event_props := e.Props()
		FileObject, _ := event_props.GetString("FileKey")

		filename, err := self.fileCache.Get(FileObject)
		if err == nil {
			event_props.Set("FileName", filename)
		}

	case CreateFile:
		event_props := e.Props()
		OpenPath, _ := event_props.GetString("OpenPath")
		FileObject, _ := event_props.GetString("FileObject")

		if FileObject != "" && OpenPath != "" {
			OpenPath = self.NormalizeFilename(OpenPath)
			event_props.Update("OpenPath", OpenPath)

			self.fileCache.Set(FileObject, OpenPath)
		}

	case FileRundown:
		event_props := e.Props()
		FileObject, _ := event_props.GetString("FileObject")
		FileName, _ := event_props.GetString("FileName")

		if FileObject != "" && FileName != "" {
			FileName = self.NormalizeFilename(FileName)
			self.fileCache.Set(FileObject, FileName)
			event_props.Update("FileName", FileName)
		}

	case SendTCPv4, RecvTCPv4, SendUDPv4, RecvUDPv4,
		SendTCPv6, RecvTCPv6, SendUDPv6, RecvUDPv6,
		DisconnectTCPv4, ReconnectTCPv4,
		DisconnectTCPv6, ReconnectTCPv6:
		event_props := e.Props()
		PID, _ := event_props.GetString("PID")
		if PID != "" {
			header := e.HeaderProps()
			header.Update("ProcessID", PID)
		}

	case StackWalk:
		tb := self.DecorateStackTraces(e)
		if tb == nil {
			return nil
		}

		// Re-emit the previous event with the backtrace
		// decoration.
		self.previousEvent.backtrace = tb
		return self.previousEvent

	case RegKCBRundown, RegCreateKCB, RegDeleteKCB:
		event_props := e.Props()
		KeyHandle, _ := event_props.GetString("KeyHandle")
		KeyName, _ := event_props.GetString("KeyName")

		if KeyName != "" && KeyHandle != "" {
			self.keysCache.Set(KeyHandle, KeyName)
		}

	case RegDeleteKey:
		event_props := e.Props()
		KeyHandle, _ := event_props.GetString("KeyHandle")

		if KeyHandle != "" {
			self.keysCache.Remove(KeyHandle)
		}

	case RegQueryValue, RegCloseKey, RegOpenKey,
		RegCreateKey, RegSetValue, RegDeleteValue:
		event_props := e.Props()
		KeyName, _ := event_props.GetString("KeyName")
		KeyHandle, _ := event_props.GetString("KeyHandle")

		// When the key handle is 0 key name is the full key path.
		if KeyHandle == "0x0" {
			event_props.Set("RegistryPath", KeyName)
			return e
		}

		resolved, err := self.keysCache.Get(KeyHandle)
		if err == nil {
			event_props.Set("RegistryPath", Join(resolved.(string), KeyName))
		}

		// Unfortunately there are many cases where the key handle is
		// not known.
		return e

	case CreateHandle:
		h := &Handle{PID: e.Header.ProcessID}

		event_props := e.Props()
		h.Object, _ = event_props.GetString("Object")
		h.Handle, _ = event_props.GetString("Handle")
		h.Name, _ = event_props.GetString("ObjectName")
		h.Type, _ = event_props.GetString("ObjectType")

		type_name, pres := self.typeNames[h.Type]
		if pres {
			event_props.Set("ObjectTypeName", type_name)
		}

	case CloseHandle:
		event_props := e.Props()
		Type, _ := event_props.GetString("ObjectType")
		ObjectName, _ := event_props.GetString("ObjectName")

		ObjectName = self.NormalizeFilename(ObjectName)
		if ObjectName != "" {
			event_props.Update("ObjectName", ObjectName)
		}

		name, pres := self.typeNames[Type]
		if pres {
			event_props.Set("ObjectTypeName", name)
		}
	}

	return e
}

func NewKernelInfoManager() *KernelInfoManager {
	res := &KernelInfoManager{
		typeNames:    GetObjectTypes(),
		keysCache:    ttlcache.NewCache(),
		processInfos: ttlcache.NewCache(),
		deviceLookup: getDeviceLookup(),
		peCache:      ttlcache.NewCache(),
		fileCache:    ttlcache.NewCache(),
	}

	res.keysCache.SetCacheSizeLimit(100000)
	res.processInfos.SetCacheSizeLimit(10000)
	res.peCache.SetCacheSizeLimit(1000)
	res.peCache.SetTTL(time.Minute * 10)
	res.fileCache.SetCacheSizeLimit(100000)

	return res
}

func Join(a, b string) string {
	a = strings.TrimSuffix(a, "\\")
	if b != "" {
		return a + "\\" + b
	}
	return a
}

func getDeviceLookup() map[string]string {
	lookup := make(map[string]string)

	systemroot := os.Getenv("SYSTEMROOT")
	if systemroot == "" {
		systemroot = "C:\\Windows"
	}
	lookup["\\SystemRoot"] = systemroot

	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}

	buffer := AllocateBuff(1024)

	for i := uint32(0); i <= 26; i++ {
		if bitmask&(1<<i) > 0 {
			drive_letter := []byte{byte(i) + 'A', ':', 0}

			res := C.QueryDosDeviceA(
				C.LPCSTR(unsafe.Pointer(&drive_letter[0])),
				C.LPSTR(unsafe.Pointer(&buffer[0])), C.DWORD(len(buffer)))
			if res > 1 {
				// Drop the final 0 because we dont need it.
				lookup[string(buffer[:res-2])] = string(drive_letter[:2])
			}

		}
	}
	return lookup
}

func (self *KernelInfoManager) Stats() *ordereddict.Dict {
	return ordereddict.NewDict().
		Set("PECache", self.peCache.GetMetrics()).
		Set("KeyCache", self.keysCache.GetMetrics()).
		Set("ProcessCache", self.processInfos.GetMetrics()).
		Set("FileCache", self.fileCache.GetMetrics())
}
