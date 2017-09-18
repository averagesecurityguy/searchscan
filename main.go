/*
Copyright (c) 2017, AverageSecurityGuy
# All rights reserved.
*/

package main

import (
	"flag"
	"fmt"
	"os"
)

type Configuration struct {
	nsePath       string
	msfauxPath    string
	username      string
	apitoken      string
	apibase       string
	pagecount     int
	nameOnly      bool
	showDesc      bool
	githubDetails bool
}

var config Configuration

func configuration() {
	config.nsePath = "/usr/share/nmap/scripts"
	config.msfauxPath = "/usr/share/metasploit-framework/modules/auxiliary/scanner"
	config.username = ""
	config.apitoken = ""
	config.apibase = "https://api.github.com/search/code?"
	config.pagecount = 10
}

func usage() {
	fmt.Println("Usage: searchscan [options] keyword")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.BoolVar(&config.showDesc, "d", false, "Show description along with name and path.")
	flag.BoolVar(&config.nameOnly, "n", false, "Search for keyword in the name only.")
	flag.BoolVar(&config.githubDetails, "g", false, "Download scripts from GitHub. Do not download by default.")

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
