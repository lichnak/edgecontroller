// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: Credentials", func() {
	var (
		creds *cce.Credentials
	)

	var testCertificate = strings.TrimSpace(`
-----BEGIN CERTIFICATE-----
MIIBNzCB3qADAgECAggUBcLhJDUGvDAKBggqhkjOPQQDAjAfMR0wGwYDVQQKExRD
b250cm9sbGVyIEF1dGhvcml0eTAeFw0xOTA1MDkyMzM1MThaFw0yMjA1MDYxNjQ3
NTVaMCExHzAdBgNVBAMMFmNKbF8wWF91Tld2TUdpWU5TNF9QU0EwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARtIFmun7tXRkXNEo+Z5jLm9k3Oo3i1OJoyZPXf/cI2
Sc5R/5l3+ydZ+M1J19moUjIPGLpU1pr5Ln4c5H+L3bd9owIwADAKBggqhkjOPQQD
AgNIADBFAiBePo41cBQAYZFCcJJfrOlPbzXTAONrnJt/NN1h16krJwIhANRhVgcl
HjqhNuXFDM1RVkkcBuAD0lQZHQJdXJGmqNju
-----END CERTIFICATE-----`)

	var testInvalidCertificate = strings.TrimSpace(`
-----BEGIN CERTIFICATE-----
000000000000000000000INVALID0000000CERTIFICATE0000000000000000000000
-----END CERTIFICATE-----`)

	BeforeEach(func() {
		creds = &cce.Credentials{
			ID:          "ysRMvw8aMviv9qPcXIlAsA",
			Certificate: testCertificate,
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "credentials"`, func() {
			Expect(creds.GetTableName()).To(Equal("credentials"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(creds.GetID()).To(Equal(
				"ysRMvw8aMviv9qPcXIlAsA"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			creds.SetID("456")

			By("Getting the updated ID")
			Expect(creds.ID).To(Equal("456"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is empty", func() {
			creds.ID = ""
			Expect(creds.Validate()).To(MatchError(
				"id cannot be empty"))
		})

		It("Should return an error if Certificate is empty", func() {
			creds.Certificate = ""
			Expect(creds.Validate()).To(MatchError(
				"certificate cannot be empty"))
		})

		It("Should return an error if Certificate is not PEM-encoded", func() {
			creds.Certificate = "123"
			Expect(creds.Validate()).To(MatchError(
				"certificate not PEM-encoded"))
		})

		It("Should return an error if Certificate is not a valid Certificate", func() {
			creds.Certificate = testInvalidCertificate
			Expect(creds.Validate()).To(MatchError(
				"certificate not a valid certificate"))
		})

		It("Should return an error if ID is not derived from Certificate public key", func() {
			creds.ID = "123"
			Expect(creds.Validate()).To(MatchError(
				"id not derived from certificate public key"))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(creds.String()).To(Equal(strings.TrimSpace(`
Credentials[
    ID: ysRMvw8aMviv9qPcXIlAsA
    Certificate: -----BEGIN CERTIFICATE-----
MIIBNzCB3qADAgECAggUBcLhJDUGvDAKBggqhkjOPQQDAjAfMR0wGwYDVQQKExRD
b250cm9sbGVyIEF1dGhvcml0eTAeFw0xOTA1MDkyMzM1MThaFw0yMjA1MDYxNjQ3
NTVaMCExHzAdBgNVBAMMFmNKbF8wWF91Tld2TUdpWU5TNF9QU0EwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARtIFmun7tXRkXNEo+Z5jLm9k3Oo3i1OJoyZPXf/cI2
Sc5R/5l3+ydZ+M1J19moUjIPGLpU1pr5Ln4c5H+L3bd9owIwADAKBggqhkjOPQQD
AgNIADBFAiBePo41cBQAYZFCcJJfrOlPbzXTAONrnJt/NN1h16krJwIhANRhVgcl
HjqhNuXFDM1RVkkcBuAD0lQZHQJdXJGmqNju
-----END CERTIFICATE-----
]`,
			)))
		})
	})
})
