package main

import (
	"os"
	"path/filepath"
	"fmt"
	"strings"
)

// Recursively search a directory files with the specified extension. Modified
// from https://gist.github.com/moongears/f1f2eec925997502a755
func findFiles(root, ext string) []string {
	var files []string

	err := filepath.Walk(root, func (path string, file os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if file.IsDir() {
			return nil
		}

		if filepath.Ext(path) == ext {
			files = append(files, path)
		}

		return nil
		})

	if err != nil {
		fmt.Println(err)
	}

	return files
}


// Wrap the given text at 80 characters. Modified from
// https://www.rosettacode.org/wiki/Word_wrap#Go
func wrap(text string, hang bool) string {
	width := 78
	words := strings.Fields(text)

	if len(words) == 0 {
		return text
	}

	wrapped := words[0]
	spaceLeft := width - len(wrapped)

	for _, word := range words[1:] {
		if len(word)+1 > spaceLeft {
			if hang {
				wrapped += "\n    " + word
				spaceLeft = width - len(word) - 4
			} else {
				wrapped += "\n" + word
				spaceLeft = width - len(word)
			}
		} else {
			wrapped += " " + word
			spaceLeft -= 1 + len(word)
		}
	}

	return wrapped
}
