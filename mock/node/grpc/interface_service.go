// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type interfaceService struct {
	nis []*elapb.NetworkInterface
}

func ifs() []*elapb.NetworkInterface {
	return []*elapb.NetworkInterface{
		{
			Id:          "if0",
			Description: "interface0",
			Driver:      elapb.NetworkInterface_KERNEL,
			Type:        elapb.NetworkInterface_NONE,
			MacAddress:  "mac0",
			Vlan:        0,
			Zones:       nil,
		},
		{
			Id:          "if1",
			Description: "interface1",
			Driver:      elapb.NetworkInterface_KERNEL,
			Type:        elapb.NetworkInterface_NONE,
			MacAddress:  "mac1",
			Vlan:        1,
			Zones:       nil,
		},
		{
			Id:          "if2",
			Description: "interface2",
			Driver:      elapb.NetworkInterface_KERNEL,
			Type:        elapb.NetworkInterface_NONE,
			MacAddress:  "mac2",
			Vlan:        2,
			Zones:       nil,
		},
		{
			Id:          "if3",
			Description: "interface3",
			Driver:      elapb.NetworkInterface_KERNEL,
			Type:        elapb.NetworkInterface_NONE,
			MacAddress:  "mac3",
			Vlan:        3,
			Zones:       nil,
		},
	}
}

func newInterfaceService() *interfaceService {
	return &interfaceService{
		nis: ifs(),
	}
}

func (s *interfaceService) reset() {
	s.nis = ifs()
}

func (s *interfaceService) Update(
	ctx context.Context,
	ni *elapb.NetworkInterface,
) (*empty.Empty, error) {
	i := s.findIndex(ni.Id)

	if i < len(s.nis) {
		s.nis[i] = ni
		return &empty.Empty{}, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Network Interface %s not found", ni.Id)
}

func (s *interfaceService) BulkUpdate(
	ctx context.Context,
	nis *elapb.NetworkInterfaces,
) (*empty.Empty, error) {
	// make sure all interfaces passed in exist
	for _, ni := range nis.NetworkInterfaces {
		if s.find(ni.Id) == nil {
			return nil, status.Errorf(
				codes.NotFound,
				"Network Interface %s not found", ni.Id)
		}
	}

	// make sure all interfaces are passed in
	for _, ni := range s.nis {
		if findInPB(nis.NetworkInterfaces, ni.Id) == len(nis.NetworkInterfaces) {
			return nil, status.Errorf(
				codes.FailedPrecondition,
				"Network Interface %s missing from request", ni.Id)
		}
	}

	for _, ni := range nis.NetworkInterfaces {
		if _, err := s.Update(ctx, ni); err != nil {
			return nil, err
		}
	}

	return &empty.Empty{}, nil
}

func (s *interfaceService) GetAll(
	context.Context,
	*empty.Empty,
) (*elapb.NetworkInterfaces, error) {
	return &elapb.NetworkInterfaces{
		NetworkInterfaces: s.nis,
	}, nil
}

func (s *interfaceService) Get(
	ctx context.Context,
	id *elapb.InterfaceID,
) (*elapb.NetworkInterface, error) {
	ni := s.find(id.Id)

	if ni != nil {
		return ni, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Network Interface %s not found", id.Id)
}

func (s *interfaceService) find(id string) *elapb.NetworkInterface {
	for _, ni := range s.nis {
		if ni.Id == id {
			return ni
		}
	}

	return nil
}

func findInPB(pbNIs []*elapb.NetworkInterface, id string) int {
	for i, pbNI := range pbNIs {
		if pbNI.Id == id {
			return i
		}
	}

	return len(pbNIs)
}

func (s *interfaceService) findIndex(id string) int {
	for i, ni := range s.nis {
		if ni.Id == id {
			return i
		}
	}

	return len(s.nis)
}
