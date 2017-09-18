package main

/*
Parse Nmap NSE scripts.
*/

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

var re_auxdesc = regexp.MustCompile(`(?m)'Description' +=> +'(.*)'`)
var re_auxdesc_m = regexp.MustCompile(`(?sm)'Description' +=> +%q{\n(.*?)}`)

func reformat(data string) string {
	data = strings.Join(strings.Fields(data), " ")
	return wrap(data, false)
}

func parseMsfaux(data []byte) string {
	var description string

	m := re_auxdesc.FindSubmatch(data)
	if m != nil {
		description = string(m[1])
	} else {
		m = re_auxdesc_m.FindSubmatch(data)
		if m != nil {
			description = reformat(string(m[1]))
		}
	}

	return description
}

func loadMsfAux(filename string) (scanner, error) {
	var msfaux scanner

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return msfaux, err
	}

	msfaux.SetName(filepath.Base(filename))
	msfaux.SetPath(filename)
	msfaux.SetDescription(parseMsfaux(data))

	return msfaux, nil
}
