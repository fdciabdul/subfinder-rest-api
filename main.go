package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

type SubdomainRequest struct {
	Domain string `json:"domain"`
}

type SubdomainResponse struct {
	Subdomains []string `json:"subdomains"`
}

func main() {
	http.HandleFunc("/enumerate", EnumerateHandler)
	log.Println("Starting server on :8080")
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func EnumerateHandler(w http.ResponseWriter, r *http.Request) {
	var req SubdomainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	subdomains, err := EnumerateSubdomains(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := SubdomainResponse{Subdomains: subdomains}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func EnumerateSubdomains(domain string) ([]string, error) {
	subfinderOpts := &runner.Options{
		Threads:            100,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	log.SetFlags(0)
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create subfinder runner: %v", err)
	}

	output := &bytes.Buffer{}
	if err = subfinder.EnumerateSingleDomainWithCtx(context.Background(), domain, []io.Writer{output}); err != nil {
		return nil, fmt.Errorf("failed to enumerate single domain: %v", err)
	}

	subdomains := bytes.Split(output.Bytes(), []byte("\n"))
	var result []string
	for _, subdomain := range subdomains {
		if len(subdomain) > 0 {
			result = append(result, string(subdomain))
		}
	}

	return result, nil
}
