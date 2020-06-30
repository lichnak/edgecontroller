// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package telemetry_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"

	"github.com/open-ness/common/log"
	"github.com/open-ness/edgecontroller/telemetry"
)

var _ = Describe("Telemetry", func() {
	Describe("StatsD", func() {
		var (
			buf *Buffer
		)

		BeforeEach(func() {
			buf = NewBuffer()
		})

		Context("TLS", func() {
			var (
				conn    *tls.Conn
				cleanup func() error
			)

			BeforeEach(func() {
				// Start a TLS listener
				lis, err := net.Listen("tcp", "localhost:0")
				Expect(err).NotTo(HaveOccurred())
				conf := newTLSConf(telemetry.StatsdSNI)
				lis = tls.NewListener(lis, conf)

				// Start a mock statsd service and set cleanup
				errC := make(chan error, 1)
				cleanup = func() error {
					lisErr := lis.Close()
					if srvErr := <-errC; srvErr != nil {
						return srvErr
					}
					return lisErr
				}
				go func() { errC <- telemetry.WriteToByLine(buf, 0, telemetry.AcceptTCP(lis)) }()

				// Dial to the mock statsd server over TLS
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				clientConf := conf.Clone()
				clientConf.ServerName = telemetry.StatsdSNI
				netConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", lis.Addr().String())
				Expect(err).NotTo(HaveOccurred())
				conn = tls.Client(netConn, clientConf)
				Expect(conn.Handshake()).To(Succeed())
			})

			AfterEach(func() {
				if cleanup != nil {
					Expect(cleanup()).To(MatchError(ContainSubstring(
						"use of closed network connection",
					)))
				}
				Expect(conn.Close()).To(Succeed())
			})

			It("should write a statsd gauge", func() {
				g := "mec.smart-edge.telemetry:testgauge|1\n"
				Expect(fmt.Fprint(conn, g)).To(Equal(len(g)))
				Eventually(buf).Should(Say(g))
			})

		})

		Context("UDP", func() {
			var (
				addr    = "127.0.0.1:10514"
				conn    net.Conn
				cleanup func() error
			)

			BeforeEach(func() {
				// Start a mock statsd service and set cleanup
				ctx, cancel := context.WithCancel(context.Background())
				errC := make(chan error, 1)
				cleanup = func() error {
					cancel()
					return <-errC
				}
				go func() {
					errC <- telemetry.WriteToByLine(buf,
						telemetry.MaxUDPPacketSize+1,
						telemetry.AcceptUDP(ctx, addr),
					)
				}()

				// Dial to the mock statsd server
				Eventually(func() error {
					var err error
					conn, err = net.Dial("udp", addr)
					return err
				}).Should(Succeed())
			})

			AfterEach(func() {
				if cleanup != nil {
					Expect(cleanup()).To(MatchError(context.Canceled))
				}
				Expect(conn.Close()).To(Succeed())
			})

			It("should write a statsd gauge", func() {
				g := "mec.smart-edge.telemetry:testgauge|1"
				// write N times to make it more likely that UDP packet is
				// received
				for i := range make([]struct{}, 20) {
					log.Debugf("Sending UDP packet #%d", i+1)
					if _, err := fmt.Fprint(conn, g); err != nil {
						log.Errf("error writing to UDP conn: %v", err)
					}
					time.Sleep(50 * time.Millisecond)
				}
				Eventually(buf, 2).Should(Say(g + "\n"))
			})
		})

		Context("DTLS", func() { /* TODO */ })
	})

	Describe("Syslog", func() {
		var (
			buf    *Buffer
			logger *log.Logger
		)

		BeforeEach(func() {
			buf = NewBuffer()
			logger = &log.Logger{}
		})

		Context("TLS", func() {
			var (
				cleanup func() error
			)

			BeforeEach(func() {
				// Start a TLS listener
				lis, err := net.Listen("tcp", "localhost:0")
				Expect(err).NotTo(HaveOccurred())
				conf := newTLSConf(telemetry.SyslogSNI)
				lis = tls.NewListener(lis, conf)

				// Start a mock syslog service and set cleanup
				errC := make(chan error, 1)
				cleanup = func() error {
					lisErr := lis.Close()
					if srvErr := <-errC; srvErr != nil {
						return srvErr
					}
					return lisErr
				}
				go func() { errC <- telemetry.WriteToByLine(buf, 0, telemetry.AcceptTCP(lis)) }()

				// Dial to the mock syslog server over TLS
				clientConf := conf.Clone()
				clientConf.ServerName = telemetry.SyslogSNI
				Expect(
					logger.ConnectSyslogTLS(lis.Addr().String(), clientConf),
				).To(Succeed())
			})

			AfterEach(func() {
				if cleanup != nil {
					Expect(cleanup()).To(MatchError(ContainSubstring(
						"use of closed network connection",
					)))
				}
			})

			It("Sends one syslog line to a mock syslog server", func() {
				logger.Alert("BAD THINGS")
				Eventually(buf).Should(Say("BAD THINGS"))
			})

			It("Sends multiple syslog lines to a mock syslog server", func() {
				logger.Alert("THING ONE")
				Eventually(buf).Should(Say("THING ONE\n"))
				logger.Alert("THING TWO")
				Eventually(buf).Should(Say("THING TWO\n"))
			})
		})
	})
})
