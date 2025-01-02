package etw

/*
  #cgo LDFLAGS: -lntdll

   #include "session.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// From https://github.com/winsiderss/systeminformer/tree/master/phnt
const (
	ObjectTypesInformation uint32 = 3
)

func AllocateBuff(length int) []byte {
	buffer := make([]byte, length+8)
	offset := int(uintptr(unsafe.Pointer(&buffer[0])) & uintptr(0xF))

	return buffer[offset:]
}

func GetObjectTypes() map[string]string {
	res := make(map[string]string)

	buffer := AllocateBuff(1024 * 10)
	start_offset := unsafe.Pointer(&buffer[0])
	length := C.ULONG(0)
	status := C.NtQueryObject(nil,
		C.OBJECT_INFORMATION_CLASS(ObjectTypesInformation),
		C.PVOID(start_offset),
		C.ULONG(len(buffer)),
		&length)

	size_of_OBJECT_TYPE_INFORMATION := uint64(unsafe.Sizeof(*C.PMyOBJECT_TYPE_INFORMATION(nil)))

	if status == 0 && length > 1024 {
		offset := uint64(0)
		// Parse the type buffer.
		number_of_types := int(binary.LittleEndian.Uint64(buffer[offset:]))

		offset += 8

		// These are just packed OBJECT_TYPE_INFORMATION structs.
		for i := 0; i < number_of_types; i++ {
			if offset+size_of_OBJECT_TYPE_INFORMATION > uint64(len(buffer)) {
				break
			}

			type_info := C.PMyOBJECT_TYPE_INFORMATION(
				unsafe.Pointer(&buffer[offset]))

			length := uint64(type_info.TypeName.Length)
			alloc_length := uint64(type_info.TypeName.MaximumLength)
			str_offset := uint64(uintptr(
				unsafe.Pointer(type_info.TypeName.Buffer))) -
				uint64(uintptr(start_offset))

			if str_offset+length > uint64(len(buffer)) {
				break
			}

			name := UTF16BytesToUTF8(
				buffer[str_offset:str_offset+length], binary.LittleEndian)
			id := type_info.TypeIndex
			offset = str_offset + alloc_length

			// Round up to the next 8 byte boundary
			if offset%8 != 0 {
				offset = 8 + offset - offset%8
			}

			res[fmt.Sprintf("%d", id)] = name
		}
	}
	return res
}

func UTF16BytesToUTF8(b []byte, o binary.ByteOrder) string {
	if len(b) < 2 {
		return ""
	}

	if b[0] == 0xff && b[1] == 0xfe {
		o = binary.BigEndian
		b = b[2:]
	} else if b[0] == 0xfe && b[1] == 0xff {
		o = binary.LittleEndian
		b = b[2:]
	}

	utf := make([]uint16, (len(b)+(2-1))/2)

	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = o.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}

	return string(utf16.Decode(utf))
}
