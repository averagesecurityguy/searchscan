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
	cachePath     string
	username      string
	apitoken      string
	apibase       string
	nameOnly      bool
	showDesc      bool
	githubCache   bool
}

var config Configuration

func configuration() {
	config.nsePath = "/usr/share/nmap/scripts"
	config.msfauxPath = "/usr/share/metasploit-framework/modules/auxiliary/scanner"
	config.cachePath = ""
	config.username = ""
	config.apitoken = ""
	config.apibase = "https://api.github.com/search/code?"
}

func usage() {
	fmt.Println("Usage: searchscan [options] keyword")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.BoolVar(&config.showDesc, "d", false, "Show description along with name and path.")
	flag.BoolVar(&config.nameOnly, "n", false, "Search for keyword in the name only.")
	flag.BoolVar(&config.githubCache, "c", false, "Build the GitHub cache.")

	flag.Parse()
	configuration()

	if config.githubCache == true {
		err := buildGithubCache("nse")
		if err != nil {
			fmt.Println(err)
			os.Exit(0)
		}

		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(0)
	}

	for _, s := range findScanners(flag.Arg(0)) {
		if config.showDesc == true {
			fmt.Println(s.Detail())
		} else {
			fmt.Println(s.Summary())
		}
	}
}
