package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

type DNSRecord struct {
	A    []string `json:"A,omitempty"`
	AAAA []string `json:"AAAA,omitempty"`
	MX   []string `json:"MX,omitempty"`
	TXT  []string `json:"TXT,omitempty"`
	SOA  []string `json:"SOA,omitempty"`
	CAA  []string `json:"CAA,omitempty"`
}

type IPData map[string]DNSRecord

type DNSData map[string]IPData

type ErrorResponse struct {
	Error string `json:"error"`
}

type DomainRequest struct {
	Domain string `json:"domain"`
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

// GET /dns-records — return JSON
func dnsRecordsHandler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
		return
	}

	filePath := filepath.Join("..", "dns_output.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read file: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Failed to read dns_output.json"})
		return
	}

	var dnsData DNSData
	if err := json.Unmarshal(data, &dnsData); err != nil {
		log.Printf("Failed to parse JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON format"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dnsData)
}

// POST /resolve — run script with domain
func resolveHandler(w http.ResponseWriter, r *http.Request) {
    enableCors(&w)

    if r.Method == http.MethodOptions {
        w.WriteHeader(http.StatusNoContent)
        return
    }

    if r.Method != http.MethodPost {
        w.WriteHeader(http.StatusMethodNotAllowed)
        json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed"})
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        log.Println("Failed to read body:", err)
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request body"})
        return
    }
    defer r.Body.Close()

    var req DomainRequest
    if err := json.Unmarshal(body, &req); err != nil || req.Domain == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON or missing domain"})
        return
    }

    // Run script (replace with your actual script path and logic)
    cmd := exec.Command("python3", "dns_test.py", req.Domain)
    cmd.Dir = ".." // script and dns_output.json are one directory up
    output, err := cmd.CombinedOutput()

    // Return 200 OK, but ensure the response includes any errors or domain issues
    if err != nil {
        log.Printf("Script failed: %v\nOutput: %s", err, string(output))
        // Send response with an error message, but status is OK (200)
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"status": "failure", "message": "Failed to resolve domain"})
        return
    }

    // If script succeeds, send a success response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}




func main() {
	http.HandleFunc("/dns-records", dnsRecordsHandler)
	http.HandleFunc("/resolve", resolveHandler)

	fmt.Println("Server running at http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

