package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"os"
	"strings"
	"time"
)

var re_next = regexp.MustCompile(`^<(https://api.github.com.*)>; rel="next"`)

type result struct {
	Items []item `json:"items"`
}

type item struct {
	Name string `json:"name"`
	Sha  string `json:"sha"`
	Url  string `json:"html_url"`
}

func request(query string) ([]byte, string, error) {
	var body []byte

	next := ""
	url := config.apibase + query
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(config.username, config.apitoken)
	resp, err := client.Do(req)

	switch {
	case err != nil:
		return body, next, err
	case resp.StatusCode == 404:
		return body, next, errors.New("Endpoint not found or invalid authentication.")
	default:
	}

	defer resp.Body.Close()

	// Get the next link for our search
	links := strings.Split(resp.Header.Get("link"), ", ")
	for _, l := range(links) {
		m := re_next.FindStringSubmatch(l)
		if m != nil {
			next = m[1]
			break
		}
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, next, errors.New("Could not read response.")
	}

	return body, next, nil
}

func download(url string) {
	script := path.Base(url)
	filename := filepath.Join(config.cachePath, script)

	fmt.Printf("Downloading %s\n", script)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Could not access %s.\n", url)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Could not read HTTP response.")
	}

	f, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Could not create file %s\n", filename)
	}

	_, err = f.WriteString(fmt.Sprintf("\n-- @GitHub %s\n", url))
	if err != nil {
		fmt.Printf("Could not write file.")
	}

	_, err = f.Write(body)
	if err != nil {
		fmt.Printf("Could not write file.")
	}
}

// Build a cache of NSE scripts from GitHub
func buildGithubCache(stype string) error {
	var query string
	var result result
	var items []item
	var nmaps []string

	fmt.Printf("Building GitHub cache for %s scripts.\n", stype)

	if config.username == "" || config.apitoken == "" {
		return errors.New("Invalid Github credentials. Cannot build GitHub cache.")
	}

	if _, err := os.Stat(config.cachePath); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("GitHub cache path (%s) does not exist.\n", config.cachePath))
	}

	switch {
	case stype == "nse":
		query = "nse in:path language:lua extension:nse"
	case stype == "msfaux":
		query = ""
	}

	params := url.Values{}
	params.Set("q", query)
	params.Set("per_page", "100")
	params.Set("page", "1")

	resp, next, err := request(params.Encode())
	if err != nil {
		return err
	}
	json.Unmarshal(resp, &result)
	items = append(items, result.Items...)

	for {
		// No more results. Quit
		if next == "" {
			break
		}

		resp, next, err = request(next[35:])
		if err != nil {
			return err
		}
		json.Unmarshal(resp, &result)
		items = append(items, result.Items...)

		time.Sleep(2500 * time.Millisecond)
	}

	// Flag items from the Nmap repo so we can remove any files that are
	// duplicates.
	urls := make(map[string] string)
	for _, item := range items {
		switch {
		case strings.HasPrefix(item.Url, "https://github.com/nmap/"):
			nmaps = append(nmaps, item.Sha)
		default:
			urls[item.Sha] = item.Url
		}
	}

	// Use the SHA1 hash to delete files that are duplicates of official Nmap NSEs
	for _, sha := range nmaps {
		delete(urls, sha)
	}

	fmt.Printf("Downloading %d %s scripts from Github.\n", len(urls), stype)
	for _, url := range urls {
		// Need the raw URL.
		url = strings.Replace(url, "github.com", "raw.githubusercontent.com", 1)
		url = strings.Replace(url, "blob/", "", 1)
		download(url)
	}

	return nil
}
