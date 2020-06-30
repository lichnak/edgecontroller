// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package pki_test

import (
	"crypto"
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

var _ = Describe("Key Persistence", func() {
	var (
		err     error
		tmpDir  string
		keyFile string
		key     crypto.PrivateKey
	)

	BeforeEach(func() {
		By("Creating a temp directory for test artifacts")
		tmpDir = filepath.Join(
			os.TempDir(),
			"github.com/open-ness/edgecontroller/pki/key_test",
		)
		keyFile = filepath.Join(tmpDir, "key.pem")

		By("Removing any existing test artifacts in the temp directory")
		err = os.RemoveAll(tmpDir)
		Expect(err).ToNot(HaveOccurred())

		By(fmt.Sprintf("Creating key_test directory: %s", tmpDir))
		err = os.MkdirAll(tmpDir, 0777)
		Expect(err).ToNot(HaveOccurred())

		By("Generating a private key")
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("StoreKey", func() {
		It("Should store a private key on disk", func() {
			By("Storing the key on disk")
			err = pki.StoreKey(key, keyFile)
			Expect(err).ToNot(HaveOccurred())

			By("Reading the stored key file")
			contents, err := ioutil.ReadFile(keyFile)
			Expect(err).ToNot(HaveOccurred())

			By("Decoding the PEM encoded key")
			block, _ := pem.Decode(contents)
			Expect(err).ToNot(HaveOccurred())

			By("Verifying key")
			storedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedKey).To(Equal(key))
		})
	})

	Describe("LoadKey", func() {
		It("Should load a private key from disk", func() {
			By("Storing a key on disk")
			der, err := x509.MarshalPKCS8PrivateKey(key)
			Expect(err).ToNot(HaveOccurred())

			file, err := os.Create(keyFile)
			Expect(err).ToNot(HaveOccurred())
			defer file.Close()

			err = pem.Encode(
				file,
				&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: der,
				},
			)
			Expect(err).ToNot(HaveOccurred())

			By("Verifying stored key")
			storedKey, err := pki.LoadKey(keyFile)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedKey).To(Equal(key))
		})
	})
})
