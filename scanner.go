package main

import (
	"bytes"
	"fmt"
	"strings"
)

// Struct and methods to store script information
type scanner struct {
	name        string
	path        string
	description string
}

func (s *scanner) SetName(name string) {
	s.name = name
}

func (s *scanner) SetPath(path string) {
	s.path = path
}

func (s *scanner) SetDescription(desc string) {
	s.description = desc
}

func (s *scanner) Detail() string {
	var str bytes.Buffer

	str.WriteString(fmt.Sprintf("%s\n", s.name))
	str.WriteString(fmt.Sprintf("%s\n", strings.Repeat("=", len(s.name))))
	str.WriteString(fmt.Sprintf("Path: %s\n\n", s.path))
	str.WriteString(fmt.Sprintf("%s\n\n", s.description))

	return str.String()
}

func (s *scanner) Summary() string {
	return fmt.Sprintf("%s - %s", s.name, s.path)
}

func (s *scanner) Check(keyword string, nameOnly bool) bool {
	keyword = strings.ToLower(keyword)
	name := strings.ToLower(s.name)
	desc := strings.ToLower(s.description)

	if nameOnly == true {
		return strings.Contains(name, keyword)
	} else {
		return strings.Contains(name, keyword) || strings.Contains(desc, keyword)
	}
}

func loadScanners(stype string) []scanner {
	var scanners []scanner
	var files []string
	var loader func(string) (scanner, error)

	switch {
	case stype == "nse":
		fmt.Println("Searching local Nmap NSE scripts.")
		files = findFiles(config.nsePath, ".nse")
		loader = loadNSE
	case stype == "msfaux":
		fmt.Println("Searching local MSF Auxiliary scripts.")
		files = findFiles(config.msfauxPath, ".rb")
		loader = loadMsfAux
	case stype == "github":
		fmt.Println("Searching Github NSE scripts.")
		files = githubFiles()
		loader = loadGithubNse
	default:
		return scanners
	}

	for _, f := range files {
		scanner, err := loader(f)

		if err != nil {
			fmt.Println(err)
			continue
		}

		scanners = append(scanners, scanner)
	}

	return scanners
}

func findScanners(keyword string) []scanner {
	var scanners []scanner

	scanners = append(scanners, loadScanners("nse")...)
	scanners = append(scanners, loadScanners("msfaux")...)
	scanners = append(scanners, loadScanners("github")...)

	var found []scanner
	for _, s := range scanners {
		if s.Check(keyword, config.nameOnly) {
			found = append(found, s)
		}
	}

	return found
}
