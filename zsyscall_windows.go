// Code generated by 'go generate'; DO NOT EDIT.

package getsystem

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

var _ unsafe.Pointer

var (
	bpGlobal, bperr = bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
)

func NtAdjustPrivilegesToken(TokenHandle windows.Token, DisableAllPrivileges bool, NewState *windows.Tokenprivileges, BufferLength uint32, PreviousState *windows.Tokenprivileges, ReturnLength *uint32) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtAdjustPrivilegesToken")
	if e != nil {
		err = e
		return
	}
	var _p0 uint32
	if DisableAllPrivileges {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(TokenHandle), uintptr(_p0), uintptr(unsafe.Pointer(NewState)), uintptr(BufferLength), uintptr(unsafe.Pointer(PreviousState)), uintptr(unsafe.Pointer(ReturnLength)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtOpenProcessToken(ProcessHandle windows.Handle, DesiredAccess windows.ACCESS_MASK, TokenHandle *windows.Token) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtOpenProcessToken")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(ProcessHandle), uintptr(DesiredAccess), uintptr(unsafe.Pointer(TokenHandle)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtSetInformationToken(TokenHandle windows.Token, TokenInformationClass uint32, TokenInformation *byte, TokenInformationLength uint32) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtSetInformationToken")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(TokenHandle), uintptr(TokenInformationClass), uintptr(unsafe.Pointer(TokenInformation)), uintptr(TokenInformationLength))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtDuplicateToken(TokenHandle windows.Token, DesiredAccess windows.ACCESS_MASK, ObjectAttributes *windows.OBJECT_ATTRIBUTES, EffectiveOnly bool, TokenType int, NewToken *windows.Token) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtDuplicateToken")
	if e != nil {
		err = e
		return
	}
	var _p0 uint32
	if EffectiveOnly {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(TokenHandle), uintptr(DesiredAccess), uintptr(unsafe.Pointer(ObjectAttributes)), uintptr(_p0), uintptr(TokenType), uintptr(unsafe.Pointer(NewToken)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}

func NtOpenProcess(processHandle *windows.Handle, desiredAccess windows.ACCESS_MASK, objectAttributes *windows.OBJECT_ATTRIBUTES, clientID *ClientID) (err error) {
	if bpGlobal == nil {
		err = fmt.Errorf("BananaPhone uninitialised: %s", bperr.Error())
		return
	}

	sysid, e := bpGlobal.GetSysID("NtOpenProcess")
	if e != nil {
		err = e
		return
	}
	r1, _ := bananaphone.Syscall(sysid, uintptr(unsafe.Pointer(processHandle)), uintptr(desiredAccess), uintptr(unsafe.Pointer(objectAttributes)), uintptr(unsafe.Pointer(clientID)))
	if r1 != 0 {
		err = fmt.Errorf("error code: %x", r1)
	}
	return
}