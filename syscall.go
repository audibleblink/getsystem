package getsystem

import "golang.org/x/sys/windows"

type ClientID struct {
	UniqueProcess windows.Handle
	UniqueThread  windows.Handle
}

//dsys NtAdjustPrivilegesToken( TokenHandle windows.Token, DisableAllPrivileges bool, NewState *windows.Tokenprivileges, BufferLength uint32, PreviousState *windows.Tokenprivileges, ReturnLength *uint32 ) (err error)

//dsys NtOpenProcessToken( ProcessHandle windows.Handle, DesiredAccess windows.ACCESS_MASK, TokenHandle *windows.Token ) (err error)

//dsys NtSetInformationToken( TokenHandle windows.Token, TokenInformationClass uint32, TokenInformation *byte, TokenInformationLength uint32 )   (err error)

//dsys NtDuplicateToken( TokenHandle windows.Token, DesiredAccess windows.ACCESS_MASK, ObjectAttributes *windows.OBJECT_ATTRIBUTES, EffectiveOnly bool, TokenType int, NewToken *windows.Token ) (err error)

//dsys NtOpenProcess(processHandle *windows.Handle, desiredAccess windows.ACCESS_MASK, objectAttributes *windows.OBJECT_ATTRIBUTES, clientID *ClientID) (err error)

//go:generate go run github.com/nodauf/bananaWinSyscall/mkdirectwinsyscall -output zsyscall_windows.go syscall.go
