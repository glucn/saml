package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func main() {
	url := "http://localhost:8080/entry/"
	body := strings.NewReader("")
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		panic(err.Error())
	}
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(resp.StatusCode)
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(string(respBody))
}
