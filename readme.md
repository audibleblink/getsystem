## getsystem

small utility package for impersonating a user in the current thread or starting a new process
with a duplicated tokenl

also token privilege manipulation

must already be in a high integrity context.

Example demo in `/cmd/main.go` folder

## Available functions

```
CONSTANTS

const (
        OpenProcTokenPerms uint32 = windows.TOKEN_READ |
                windows.TOKEN_DUPLICATE |
                windows.TOKEN_IMPERSONATE
        TokenDupPerms uint32 = windows.TOKEN_QUERY |
                windows.TOKEN_DUPLICATE |
                windows.TOKEN_ASSIGN_PRIMARY |
                windows.TOKEN_ADJUST_DEFAULT |
                windows.TOKEN_ADJUST_SESSIONID

        MLUntrusted = "S-1-16-0"
)

FUNCTIONS

func DebugPriv() error
    DebugPriv enables the SeDebugPrivilege

func DemoteProcess(pid int) (err error)
    DemoteProcess will remove set SE_PRIVILEGE_REMOVED on all privs for the
    process LUID It then sets the Token Label to Untrusted

func GetTokenPrivileges(tokenH windows.Token) (tokenPrivileges windows.Tokenprivileges, err error)
    GetTokenPrivileges will retreive token privilege information and parse it to
    a windows Tokenpriveleges struct. An error is returned if the function fails
    to retrieve the initial token information

func InNewProcess(pid int, cmd string, hidden bool) error
    InNewProcess will duplicate the token from given PID and start a new process
    using the winapi's DuplicateTokenEx and StartProccessWithTokenW with the
    given command

func OnThread(pid int) error
    OnThread will steal a token from the given process. It can be other users as
    well not just system. The token will be applied to the current thread until
    revtoself is called, or the thread exits. Only certain processes can have
    their SYSTEM token stolen. You have TOKEN_OWNER in the DACL of the SYSTEM
    process in order to steal it.

func RemoveTokenPrivileges(tokenH windows.Token) (err error)
    RemoveTokenPrivileges fetches the privileges of a token and revokes them by
    applying the SE_PRIVILEGE_REMOVED privilege

func SePrivEnable(privString string) (err error)
    SePrivEnable takes a privilege name and enables it

func SetTokenLabel(tokenH windows.Token, label string) (err error)
    SetTokenLabel sets a token label for a given token

func TokenOwner(hToken windows.Token) (string, error)
    TokenOwner will resolve the primary token or thread owner of the given
    handle

func TokenOwnerFromPid(pid int) (string, error)
    TokenOwnerFromPid will resolve the primary token or thread owner of the
    given pid
```


## greetz

@slyd0g for [this article](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b) which was a huge help in understanding the inconsistencies I was seeing when testing this on different SYSTEM processes.
