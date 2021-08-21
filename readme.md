## getsystem

small utility for impersonating a user in the current thread or starting a new process
with a duplicated token.

must already be in a high integrity context.

Example demo in `/cmd/main.go` folder

## Available functions

```go
// replace the current threads effective token
func OnThread(pid int) error

// start a new process from a duplicated token
func InNewProcess(pid int, cmd string, hidden bool) error

// Enable debug privilege
func DebugPriv() error

// Enable a specific privilege
func SePrivEnable(privString string) (err error)

// Return the owner of a given token
func TokenOwner(hToken windows.Token) (string, error)
```

### Output

```
PS getsystem> go run .\cmd\ 1804
2021/08/21 11:06:04 Enabling seDebug...
2021/08/21 11:06:04 OK
2021/08/21 11:06:04 Current effective thread owner: DEMOPC\adm-user
2021/08/21 11:06:04 Beginning Token impersonation in current thread
2021/08/21 11:06:04 Current effective thread owner: NT AUTHORITY\SYSTEM
2021/08/21 11:06:04 Reverting to previous user
2021/08/21 11:06:04 Current effective thread owner: DEMOPC\adm-user
2021/08/21 11:06:04 Starting new process with duplicated token
```

## greetz

@slyd0g for [this article](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b) which was a huge help in understanding the inconsistencies I was seeing when testing this on different SYSTEM processes.
