package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

type result struct {
	Items []item `json:"items"`
}

type item struct {
	Name string `json:"name"`
	Sha  string `json:"sha"`
	Url  string `json:"html_url"`
}

func request(query string) ([]byte, error) {
	var body []byte

	url := config.apibase + query
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(config.username, config.apitoken)
	resp, err := client.Do(req)

	switch {
	case err != nil:
		return body, err
	case resp.StatusCode == 404:
		return body, errors.New("Endpoint not found or invalid authentication.")
	default:
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, errors.New("Could not read response.")
	}

	return body, nil
}

func githubFiles() []string {
	var result result
	var files []string
	var nmaps []string

	if config.username == "" || config.apitoken == "" {
		fmt.Println("Invalid Github credentials.")
		return files
	}

	urls := make(map[string]string)
	params := url.Values{}

	params.Set("q", "nse in:path language:lua extension:nse")
	params.Set("per_page", "100")

	for i := 1; i <= config.pagecount; i++ {
		params.Set("page", strconv.Itoa(i))

		resp, err := request(params.Encode())
		if err != nil {
			fmt.Println(err)
			break
		}

		json.Unmarshal(resp, &result)

		// Flag items from the Nmap repo so we can remove any files that are
		// duplicates.
		for _, item := range result.Items {
			switch {
			case strings.HasPrefix(item.Url, "https://github.com/nmap/"):
				nmaps = append(nmaps, item.Sha)
			default:
				urls[item.Sha] = item.Url
			}
		}
	}

	// Use the SHA1 hash to delete files that are duplicates of official Nmap NSEs
	for _, sha := range nmaps {
		delete(urls, sha)
	}

	for _, item := range urls {
		files = append(files, item)
	}

	return files
}

func getPage(url string) ([]byte, error) {
	var body []byte

	resp, err := http.Get(url)
	if err != nil {
		return body, err
	}

	defer resp.Body.Close()

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, errors.New("Could not read response.")
	}

	return body, nil
}

func loadGithubNse(url string) (scanner, error) {
	var github scanner

	github.SetName(path.Base(url))
	github.SetPath(url)

	if config.githubDetails == true {
		data, err := getPage(url)
		if err != nil {
			return github, err
		}

		github.SetDescription(parseNSE(data))
	}

	return github, nil
}
