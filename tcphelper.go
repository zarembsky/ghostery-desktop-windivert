package godivert

import (
	"errors"
	"syscall"
	"unsafe"
	"fmt"
)

type TCPHelper struct {
	dllHandle        syscall.Handle
	getConnectionPID uintptr
	getProcessName uintptr

}

func NewTCPHelper() (*TCPHelper, error) {
	dllHandle, err := syscall.LoadLibrary("tcphelper.dll")
	if err != nil {
		return nil, err
	}
	getConnectionPID, err := syscall.GetProcAddress(dllHandle, "GetConnectionPID")
	if err != nil {
		return nil, err
	}

	getProcessName, err1 := syscall.GetProcAddress(dllHandle, "GetProcessName")
	if err != nil {
		return nil, err1
	}
	tcpHelper := &TCPHelper{
		dllHandle:        dllHandle,
		getConnectionPID: getConnectionPID,
		getProcessName: getProcessName,
	}
	return tcpHelper, nil
}

func (th *TCPHelper) Close() {
	if th.dllHandle != 0 {
		syscall.FreeLibrary(th.dllHandle)
	}
}

func (th *TCPHelper) GetConnectionPID(srcPort int, srcIP string, addressFamily int) (int, error) {
	if th.dllHandle == 0 || th.getConnectionPID == 0 || th.getProcessName == 0 {
		return 0, errors.New("TCPHelper is not initialized")
	}
	var nargs uintptr = 3
	ret, _, callErr := syscall.Syscall(th.getConnectionPID, nargs, uintptr(srcPort), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(srcIP))), uintptr(addressFamily))
	if callErr != 0 {
		return 0, errors.New(fmt.Sprintf("syscall for getConnectionPID faled with error %s", callErr))
	}
	return int(ret), nil
}

func (th *TCPHelper) GetProcessName(pid int) (string, error) {
	if th.dllHandle == 0 || th.getConnectionPID == 0 || th.getProcessName == 0 {
		return "", errors.New("TCPHelper is not initialized")
	}
	var nargs uintptr = 3
	bufferSize := 261 //MAX_PATH in Windows is defined as 260 characters
	var array[261]uint16
	buffer := array[:]
	_, _, callErr := syscall.Syscall(th.getProcessName, nargs, uintptr(pid), uintptr(unsafe.Pointer(&buffer)), uintptr(bufferSize))
	if callErr != 0 {
		return "", errors.New(fmt.Sprintf("syscall for getProcessName faled with error %s", callErr))
	}
	return syscall.UTF16ToString(buffer), nil
}

// func GetProcessName(pid int) string, error {
// 	dllHandle, err := syscall.LoadLibrary("kernel32.dll")
// 	if err != nil {
// 		return nil, err
// 	}

//	StringBuilder buffer = new StringBuilder(1024);
//	IntPtr hprocess = Kernel32.OpenProcess(Kernel32.ProcessAccessFlags.QueryLimitedInformation, false, (uint)processId);
//	if (hprocess != IntPtr.Zero)
//	{
//		try
//		{
//			int size = buffer.Capacity;
//			if (Kernel32.QueryFullProcessImageName(hprocess, 0, buffer, ref size))
//			{
//				return buffer.ToString();
//			}
//		}
//		finally
//		{
//			Kernel32.CloseHandle(hprocess);
//		}
//	}
//	return string.Empty;

//}
