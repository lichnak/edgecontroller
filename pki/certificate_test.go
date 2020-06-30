// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"

	"github.com/open-ness/edgecontroller/pki"
)

var _ = Describe("Certificate Persistence", func() {
	var (
		err      error
		tmpDir   string
		certFile string
		key      crypto.PrivateKey
		cert     *x509.Certificate
	)

	BeforeEach(func() {
		By("Creating a temp directory for test artifacts")
		tmpDir = filepath.Join(
			os.TempDir(),
			"github.com/open-ness/edgecontroller/pki/certificate_test",
		)
		certFile = filepath.Join(tmpDir, "cert.pem")

		By("Removing any existing test artifacts in the temp directory")
		err = os.RemoveAll(tmpDir)
		Expect(err).ToNot(HaveOccurred())

		By(fmt.Sprintf("Creating certificate_test directory: %s", tmpDir))
		err = os.MkdirAll(tmpDir, 0777)
		Expect(err).ToNot(HaveOccurred())

		By("Generating a private key")
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		Expect(err).ToNot(HaveOccurred())

		By("Generating a certificate")
		cert, err = generateCert(key)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("StoreCertificate", func() {
		It("Should store a certificate on disk", func() {
			By("Storing the certificate on disk")
			err = pki.StoreCertificate(certFile, cert)
			Expect(err).ToNot(HaveOccurred())

			By("Reading the stored certificate file")
			bytes, err := ioutil.ReadFile(certFile)
			Expect(err).ToNot(HaveOccurred())

			By("Decoding the PEM encoded certificate")
			block, _ := pem.Decode(bytes)
			Expect(err).ToNot(HaveOccurred())

			By("Verifying certificate")
			storedCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedCert).To(Equal(cert))
		})
	})

	Describe("LoadCertificate", func() {
		It("Should load a certificate from disk", func() {
			By("Storing a certificate on disk")
			file, err := os.Create(certFile)
			Expect(err).ToNot(HaveOccurred())
			defer file.Close()

			err = pem.Encode(
				file,
				&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				},
			)
			Expect(err).ToNot(HaveOccurred())

			By("Verifying stored certificate")
			storedCert, err := pki.LoadCertificate(certFile)
			Expect(err).ToNot(HaveOccurred())
			Expect(storedCert).To(Equal(cert))
		})
	})
})

func generateCert(key crypto.PrivateKey) (*x509.Certificate, error) {
	var (
		err      error
		k        crypto.Signer
		ok       bool
		template *x509.Certificate
		der      []byte
	)

	if k, ok = key.(crypto.Signer); !ok {
		return nil, errors.Wrap(err, "unable to parse key")
	}

	template = &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Organization: []string{"Mock Certificate"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	if der, err = x509.CreateCertificate(rand.Reader, template, template, k.Public(), key); err != nil {
		return nil, errors.Wrap(err, "unable to create certificate")
	}

	return x509.ParseCertificate(der)
}
