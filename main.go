package main

import (
	"encoding/json"
	"fmt"
	"github.com/sbroekhoven/caacheck/caa"
	"os"
	"strings"
)

func main() {
	hostname := strings.ToLower(os.Args[1])
	nameserver := strings.ToLower(os.Args[2])
	fullarg := strings.ToLower(os.Args[3])
	var full bool
	if fullarg == "true" {
		full = true
	} else {
		full = false
	}

	caadata := caa.Get(hostname, nameserver, full)

	data, err := json.MarshalIndent(caadata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", data)
}
