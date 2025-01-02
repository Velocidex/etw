//go:build windows && amd64
// +build windows,amd64

package etw

// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
func inKernelSpace(ptr uintptr) bool {
	return ptr > 0x7FFFFFFFFFF
}
