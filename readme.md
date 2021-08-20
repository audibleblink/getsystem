## getsystem

small utility for impersonating a user in the current thread or starting a new process
with a duplicated token.

Example demo in `/cmd/main.go` folder

## Available functions

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

