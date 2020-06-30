// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/open-ness/edgecontroller/pki"
)

var _ = Describe("Controller CA", func() {
	var (
		err    error
		tmpDir string
	)

	BeforeEach(func() {
		By("Creating a temp directory for test artifacts")
		tmpDir = filepath.Join(
			os.TempDir(),
			"github.com/open-ness/edgecontroller/pki/ca_test",
		)

		By("Removing any existing test artifacts in the temp directory")
		err = os.RemoveAll(tmpDir)
		Expect(err).ToNot(HaveOccurred())

		By(fmt.Sprintf("Creating ca_test directory: %s", tmpDir))
		err = os.MkdirAll(tmpDir, 0777)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("InitRootCA", func() {
		It("Should create and persist root CA if one does not exist", func() {
			By("Initializing root CA")
			rootCA, err := pki.InitRootCA(tmpDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(rootCA.Cert).ToNot(BeNil())
			Expect(rootCA.Key).ToNot(BeNil())

			By("Verifying the certificate was stored on disk")
			_, err = os.Stat(filepath.Join(tmpDir, "cert.pem"))
			Expect(err).ToNot(HaveOccurred())

			contents, err := ioutil.ReadFile(filepath.Join(tmpDir, "cert.pem"))
			Expect(err).ToNot(HaveOccurred())

			block, _ := pem.Decode(contents)
			Expect(err).ToNot(HaveOccurred())

			storedCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedCert).To(Equal(rootCA.Cert))

			By("Verifying the key was stored on disk")
			_, err = os.Stat(filepath.Join(tmpDir, "key.pem"))
			Expect(err).ToNot(HaveOccurred())

			contents, err = ioutil.ReadFile(filepath.Join(tmpDir, "key.pem"))
			Expect(err).ToNot(HaveOccurred())

			block, _ = pem.Decode(contents)
			Expect(err).ToNot(HaveOccurred())

			storedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedKey).To(Equal(rootCA.Key))
		})

		It("Should load root CA if one already exists", func() {
			By("Initializing root CA")
			rootCA1, err := pki.InitRootCA(tmpDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(rootCA1.Cert).ToNot(BeNil())
			Expect(rootCA1.Key).ToNot(BeNil())

			By("Initializing root CA again")
			rootCA2, err := pki.InitRootCA(tmpDir)
			Expect(err).ToNot(HaveOccurred())
			Expect(rootCA2.Cert).ToNot(BeNil())
			Expect(rootCA2.Key).ToNot(BeNil())

			By("Verifying the certificates are equivalent")
			Expect(rootCA1.Cert).To(Equal(rootCA2.Cert))

			By("Verifying the keys are equivalent")
			Expect(rootCA1.Key).To(Equal(rootCA2.Key))
		})

		Context("Certificate on disk was signed with a different key", func() {
			It("Should generate a new CA certificate", func() {
				By("Initializing root CA")
				rootCA1, err := pki.InitRootCA(tmpDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(rootCA1.Cert).ToNot(BeNil())

				By("Generating a new private key")
				key2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				Expect(err).ToNot(HaveOccurred())

				By("Signing a new certificate")
				cert2, err := generateCert(key2)
				Expect(err).ToNot(HaveOccurred())

				By("Replacing original CA certificate with the new certificate")
				err = pki.StoreCertificate(
					filepath.Join(tmpDir, "cert.pem"),
					cert2,
				)
				Expect(err).ToNot(HaveOccurred())

				By("Initializing root CA again")
				rootCA3, err := pki.InitRootCA(tmpDir)
				Expect(err).ToNot(HaveOccurred())
				Expect(rootCA1.Cert).ToNot(BeNil())

				By("Verifying the loaded CA certificate is unique")
				Expect(rootCA3.Cert).ToNot(Equal(rootCA1.Cert))
				Expect(rootCA3.Cert).ToNot(Equal(cert2))
			})
		})
	})
})
