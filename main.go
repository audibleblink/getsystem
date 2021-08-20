package main

import (
	"log"

	"github.com/audibleblink/getsystem/getsystem"
)

func main() {
	pid := 1804

	err := getsystem.DebugPriv()
	if err != nil {
		log.Fatal(err)
	}

	err = getsystem.InNewProcess(pid, `c:\windows\system32\cmd.exe`, false)
	if err != nil {
		log.Fatal(err)
	}
}
