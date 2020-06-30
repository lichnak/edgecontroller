// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients

import (
	"context"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"github.com/pkg/errors"
)

// DNSServiceClient wraps the PB client.
type DNSServiceClient struct {
	PBCli elapb.DNSServiceClient
}

// NewDNSServiceClient creates a new client.
func NewDNSServiceClient(conn *grpc.ClientConn) *DNSServiceClient {
	return &DNSServiceClient{
		conn.NewDNSServiceClient(),
	}
}

// SetA sets a DNS A record.
func (c *DNSServiceClient) SetA(
	ctx context.Context,
	record *cce.DNSARecord,
) error {
	_, err := c.PBCli.SetA(
		ctx,
		&elapb.DNSARecordSet{
			Name:   record.Name,
			Values: record.IPs,
		})

	if err != nil {
		return errors.Wrap(err, "error setting A records")
	}

	return nil
}

// DeleteA deletes a DNS A record.
func (c *DNSServiceClient) DeleteA(
	ctx context.Context,
	record *cce.DNSARecord,
) error {
	_, err := c.PBCli.DeleteA(
		ctx,
		&elapb.DNSARecordSet{
			Name:   record.Name,
			Values: record.IPs,
		})

	if err != nil {
		return errors.Wrap(err, "error deleting A records")
	}

	return nil
}

// SetForwarders sets DNS forwarders.
func (c *DNSServiceClient) SetForwarders(
	ctx context.Context,
	forwarders []*cce.DNSForwarder,
) error {
	var ips []string
	for _, forwarder := range forwarders {
		ips = append(ips, forwarder.IP)
	}

	_, err := c.PBCli.SetForwarders(ctx, &elapb.DNSForwarders{
		IpAddresses: ips,
	})

	if err != nil {
		return errors.Wrap(err, "error setting forwarders")
	}

	return nil
}

// DeleteForwarders sets DNS forwarders.
func (c *DNSServiceClient) DeleteForwarders(
	ctx context.Context,
	forwarders []*cce.DNSForwarder,
) error {
	var ips []string
	for _, forwarder := range forwarders {
		ips = append(ips, forwarder.IP)
	}

	_, err := c.PBCli.DeleteForwarders(ctx, &elapb.DNSForwarders{
		IpAddresses: ips,
	})

	if err != nil {
		return errors.Wrap(err, "error deleting forwarders")
	}

	return nil
}
