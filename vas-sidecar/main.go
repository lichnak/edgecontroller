// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"eaa"
)

// VASInfo describes the video analytics service
type VASInfo struct {
	Platform    string `json:"platform"`
	ID          string `json:"id"`
	Namespace   string `json:"namespace"`
	EndpointURI string `json:"endpointURI"`
	Description string `json:"description"`
	Framework   string `json:"framework"`
	Pipelines []string `json:"pipelines"`
}

// Is there any need to define structs to contain parameters?
type VASGetPipelines struct {
	Description string          `json:"description,omitempty"`
	Name        string          `json:"name,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
	Type        string          `json:"type,omitempty"`
	Version     string          `json:"version,omitempty"`
}

//Connectivity constants
const (
	EAAServerName = "eaa.openness"
	EAAServerPort = "4430"
	EAAServPort   = "800"
	EAACommonName = "eaa.openness"
)

func getCredentials(prvKey *ecdsa.PrivateKey) eaa.AuthCredentials {
	certTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "openvino:producer",
			Organization: []string{"Intel Corporation"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"hello@openness.org"},
	}

	prodCsrBytes, err := x509.CreateCertificateRequest(rand.Reader,
		&certTemplate, prvKey)
	if err != nil {
		log.Fatal(err)
	}
	csrMem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST",
		Bytes: prodCsrBytes})

	prodID := eaa.AuthIdentity{
		Csr: string(csrMem),
	}

	reqBody, err := json.Marshal(prodID)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.Post("http://"+EAAServerName+":"+EAAServPort+"/auth",
		"", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Fatal(err)
	}

	var prodCreds eaa.AuthCredentials
	err = json.NewDecoder(resp.Body).Decode(&prodCreds)
	if err != nil {
		log.Fatal(err)
	}

	return prodCreds
}

func authenticate(prvKey *ecdsa.PrivateKey) (*http.Client, error) {
	prodCreds := getCredentials(prvKey)

	x509Encoded, err := x509.MarshalECPrivateKey(prvKey)
	if err != nil {
		return nil, err
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY",
		Bytes: x509Encoded})
	prodCert, err := tls.X509KeyPair([]byte(prodCreds.Certificate),
		pemEncoded)
	if err != nil {
		return nil, err
	}

	prodCertPool := x509.NewCertPool()
	for _, cert := range prodCreds.CaPool {
		ok := prodCertPool.AppendCertsFromPEM([]byte(cert))
		if !ok {
			return nil, errors.New("Error: failed to append cert")
		}
	}

	// HTTPS client
	prodClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      prodCertPool,
				Certificates: []tls.Certificate{prodCert},
				ServerName:   EAACommonName,
			},
		},
		Timeout: 0,
	}

	return prodClient, nil
}

func activateService(client *http.Client, payload []byte) error {

	req, err := http.NewRequest("POST",
		"https://"+EAAServerName+":"+EAAServerPort+"/services",
		bytes.NewReader(payload))
	if err != nil {
		log.Printf("Service-activation request creation failed:", err)
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Service-activation request failed:", err)
		return err
	}

	err = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func deactivateService(client *http.Client) {

	req, err := http.NewRequest("DELETE",
		"https://"+EAAServerName+":"+EAAServerPort+"/services", nil)
	if err != nil {
		log.Printf("Unsubscription request creation failed:", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Unsubscription request failed:", err)
		return
	}

	err = resp.Body.Close()
	if err != nil {
		return
	}
}

// ConnectToServing ensures the attached Serving app is running, and takes the
// runtime variables
func ConnectToServing() ([]string, error) {

	// HTTP client
	client := &http.Client{
		Timeout: 0,
	}

	pipelines := make([]string, 0)
	VASPipelines := make([]VASGetPipelines, 0)

	req, err := http.NewRequest("GET",
		"http://localhost:8080/pipelines", nil)
	if err != nil {
		log.Println("GET /pipelines creation failed:", err)
		return pipelines, err
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("GET /pipelines request failed:", err)
		return pipelines, err
	}

	err = json.NewDecoder(resp.Body).Decode(&VASPipelines)
	if err != nil {
		log.Println("Service-list decode failed:", err)
		return pipelines, err
	}

	err = resp.Body.Close()
	if err != nil {
		return pipelines, err
	}

	for _, p := range VASPipelines {
		pipelines = append(pipelines, p.Name + "/" + p.Version)
	}

	return pipelines, nil
}

// StartSidecar starts a Service on EAA for VAS
func main() {

	// get service from env variables
	platform := os.Getenv("PLATFORM")

	// get framework from env variables
	framework := os.Getenv("FRAMEWORK")

	// get namespace from env variables
	namespace := os.Getenv("NAMESPACE")

	// get VAS port from env variables
	VASPort := os.Getenv("VAS_PORT")

	info := VASInfo{
		Platform: platform,
		ID: "analytics-"+framework,
		Namespace: namespace,
		EndpointURI: "http://analytics-"+framework+"."+namespace+":"+VASPort,
		Description: "Video Analytics Serving",
		Framework: framework,
	}

	pipelines, err := ConnectToServing()
	if err != nil {
		log.Fatal("Error connecting to serving: %#v", err)
		return
	}
	info.Pipelines = pipelines

	servURN := eaa.URN{
		ID:        info.ID,
		Namespace: info.Namespace,
	}

	serv := eaa.Service{
		URN:         &servURN,
		Description: "Video Analytics Service",
		EndpointURI: info.EndpointURI,
	}

	// perform CSR to authenticate and retrieve certificate
	servPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating key: %#v", err)
		return
	}

	client, err := authenticate(servPriv)
	if err != nil {
		log.Fatal("Error authenticating: %#v", err)
		return
	}

	serv.Info, _ = json.Marshal(info)

	requestByte, _ := json.Marshal(serv)

	err = activateService(client, requestByte)
	if err != nil {
		log.Fatal("Error activating service: %#v", err)
		return
	}

	loop := true
	for loop {
		time.Sleep(60 * time.Second)
	}

	deactivateService(client)
}
