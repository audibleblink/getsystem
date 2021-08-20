package main

import (
	"github.com/audibleblink/getsystem/getsystem"
)

func main() {
	pid := 1088

	err := getsystem.DebugPriv()
	if err != nil {
		panic(err)
	}

	err = getsystem.InNewProcess(pid, `c:\windows\system32\cmd.exe`, false)
	if err != nil {
		panic(err)
	}
}
