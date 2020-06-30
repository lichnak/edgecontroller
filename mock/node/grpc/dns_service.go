// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
)

type dnsService struct {
	// map of record name to records
	records map[string]*elapb.DNSARecordSet
	// map of ip address to ip address
	forwarders map[string]string
}

func newDNSService() *dnsService {
	return &dnsService{
		records:    make(map[string]*elapb.DNSARecordSet),
		forwarders: make(map[string]string),
	}
}

func (s *dnsService) reset() {
	s.records = make(map[string]*elapb.DNSARecordSet)
	s.forwarders = make(map[string]string)
}

func (s *dnsService) SetA(
	ctx context.Context,
	record *elapb.DNSARecordSet,
) (*empty.Empty, error) {
	s.records[record.Name] = record

	return &empty.Empty{}, nil
}

func (s *dnsService) DeleteA(
	ctx context.Context,
	record *elapb.DNSARecordSet,
) (*empty.Empty, error) {
	delete(s.records, record.Name)

	return &empty.Empty{}, nil
}

func (s *dnsService) SetForwarders(
	ctx context.Context,
	forwarders *elapb.DNSForwarders,
) (*empty.Empty, error) {
	for _, forwarder := range forwarders.IpAddresses {
		s.forwarders[forwarder] = forwarder
	}

	return &empty.Empty{}, nil
}

func (s *dnsService) DeleteForwarders(
	ctx context.Context,
	forwarders *elapb.DNSForwarders,
) (*empty.Empty, error) {
	for _, forwarder := range forwarders.IpAddresses {
		delete(s.forwarders, forwarder)
	}

	return &empty.Empty{}, nil
}
