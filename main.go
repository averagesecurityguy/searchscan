/*
Copyright (c) 2017, AverageSecurityGuy
# All rights reserved.

*/

package main

import (
	"fmt"
	"os"
	"flag"
)

type Configuration struct {
	nsePath    string
	msfauxPath string
	nameOnly   bool
	showDesc   bool
}

var config Configuration

func configuration () {
	config.nsePath = "/usr/share/nmap/scripts"
	config.msfauxPath = "/usr/share/metasploit-framework/modules/auxiliary/scanner"
}


func usage() {
	fmt.Println("Usage: searchscan [options] keyword")
	flag.PrintDefaults()
}

func main() {
    flag.Usage = usage
    flag.BoolVar(&config.showDesc, "d", false, "Show description along with name and path.")
    flag.BoolVar(&config.nameOnly, "n", false, "Search for keyword in the name only.")
    flag.Parse()

    if len(flag.Args()) != 1 {
    	flag.Usage()
    	os.Exit(0)
    }

	configuration()

	for _, s := range findScanners(flag.Arg(0)) {
		if config.showDesc == true {
			fmt.Println(s.Detail())
		} else {
			fmt.Println(s.Summary())
		}
	}
}
