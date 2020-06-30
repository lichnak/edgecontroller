// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"github.com/pkg/errors"
)

// InterfaceServiceClient wraps the PB client.
type InterfaceServiceClient struct {
	PBCli elapb.InterfaceServiceClient
}

// NewInterfaceServiceClient creates a new client.
func NewInterfaceServiceClient(conn *grpc.ClientConn) *InterfaceServiceClient {
	return &InterfaceServiceClient{
		conn.NewInterfaceServiceClient(),
	}
}

// Update updates a network interface.
func (c *InterfaceServiceClient) Update(
	ctx context.Context,
	ni *cce.NetworkInterface,
) error {
	_, err := c.PBCli.Update(
		ctx,
		toPBNetworkInterface(ni))

	if err != nil {
		return errors.Wrap(err, "error updating network interface")
	}

	return nil
}

// BulkUpdate updates multiple network interfaces.
func (c *InterfaceServiceClient) BulkUpdate(
	ctx context.Context,
	nis []*cce.NetworkInterface,
) error {
	var pbNIs []*elapb.NetworkInterface
	for _, ni := range nis {
		pbNIs = append(pbNIs, toPBNetworkInterface(ni))
	}

	_, err := c.PBCli.BulkUpdate(
		ctx,
		&elapb.NetworkInterfaces{
			NetworkInterfaces: pbNIs,
		})

	if err != nil {
		return errors.Wrap(err, "error bulk updating network interfaces")
	}

	return nil
}

// GetAll retrieves all network interfaces.
func (c *InterfaceServiceClient) GetAll(
	ctx context.Context,
) ([]*cce.NetworkInterface, error) {
	pbNIs, err := c.PBCli.GetAll(ctx, &empty.Empty{})

	if err != nil {
		return nil, errors.Wrap(err, "error retrieving all network interfaces")
	}

	var nis []*cce.NetworkInterface
	for _, pbNI := range pbNIs.NetworkInterfaces {
		nis = append(nis, fromPBNetworkInterface(pbNI))
	}

	return nis, nil
}

// Get retrieves a network interface.
func (c *InterfaceServiceClient) Get(
	ctx context.Context,
	id string,
) (*cce.NetworkInterface, error) {
	pbNI, err := c.PBCli.Get(
		ctx,
		&elapb.InterfaceID{
			Id: id,
		})

	if err != nil {
		return nil, errors.Wrap(err, "error retrieving network interface")
	}

	return fromPBNetworkInterface(pbNI), nil
}

func toPBNetworkInterface(ni *cce.NetworkInterface) *elapb.NetworkInterface {
	return &elapb.NetworkInterface{
		Id:                ni.ID,
		Description:       ni.Description,
		Driver:            toPBInterfaceDriver(ni.Driver),
		Type:              toPBInterfaceType(ni.Type),
		MacAddress:        ni.MACAddress,
		Vlan:              uint32(ni.VLAN),
		Zones:             ni.Zones,
		FallbackInterface: ni.FallbackInterface,
	}
}

func toPBInterfaceDriver(driver string) elapb.NetworkInterface_InterfaceDriver {
	switch driver {
	case "kernel":
		return elapb.NetworkInterface_KERNEL
	case "userspace":
		return elapb.NetworkInterface_USERSPACE
	default:
		return 0 // this should never happen
	}
}

func toPBInterfaceType(ifType string) elapb.NetworkInterface_InterfaceType {
	switch ifType {
	case "none":
		return elapb.NetworkInterface_NONE
	case "upstream":
		return elapb.NetworkInterface_UPSTREAM
	case "downstream":
		return elapb.NetworkInterface_DOWNSTREAM
	case "bidirectional":
		return elapb.NetworkInterface_BIDIRECTIONAL
	case "breakout":
		return elapb.NetworkInterface_BREAKOUT
	default:
		return 0 // this should never happen
	}
}

func fromPBNetworkInterface(pbNI *elapb.NetworkInterface) *cce.NetworkInterface {
	return &cce.NetworkInterface{
		ID:                pbNI.Id,
		Description:       pbNI.Description,
		Driver:            fromPBInterfaceDriver(pbNI.Driver),
		Type:              fromPBInterfaceType(pbNI.Type),
		MACAddress:        pbNI.MacAddress,
		VLAN:              int(pbNI.Vlan),
		Zones:             pbNI.Zones,
		FallbackInterface: pbNI.FallbackInterface,
	}
}

func fromPBInterfaceDriver(pbDriver elapb.NetworkInterface_InterfaceDriver) string {
	switch pbDriver {
	case elapb.NetworkInterface_KERNEL:
		return "kernel"
	case elapb.NetworkInterface_USERSPACE:
		return "userspace"
	default:
		return "kernel" // this should never happen
	}
}

func fromPBInterfaceType(pbIfType elapb.NetworkInterface_InterfaceType) string {
	switch pbIfType {
	case elapb.NetworkInterface_NONE:
		return "none"
	case elapb.NetworkInterface_UPSTREAM:
		return "upstream"
	case elapb.NetworkInterface_DOWNSTREAM:
		return "downstream"
	case elapb.NetworkInterface_BIDIRECTIONAL:
		return "bidirectional"
	case elapb.NetworkInterface_BREAKOUT:
		return "breakout"
	default:
		return "none" // this should never happen
	}
}
