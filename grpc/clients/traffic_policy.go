// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients

import (
	"fmt"

	cce "github.com/open-ness/edgecontroller"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
)

func toPBTrafficPolicy(id string, tp *cce.TrafficPolicy) *elapb.TrafficPolicy {
	pbPolicy := &elapb.TrafficPolicy{
		Id: id,
	}

	if tp != nil {
		for _, rule := range tp.Rules {
			pbPolicy.TrafficRules = append(
				pbPolicy.TrafficRules, toPBTrafficRule(rule))
		}
	}

	return pbPolicy
}

func toPBTrafficRule(tr *cce.TrafficRule) *elapb.TrafficRule {
	return &elapb.TrafficRule{
		Description: tr.Description,
		Priority:    uint32(tr.Priority),
		Source:      toPBTrafficSelector(tr.Source),
		Destination: toPBTrafficSelector(tr.Destination),
		Target:      toPBTrafficTarget(tr.Target),
	}
}

func toPBTrafficSelector(ts *cce.TrafficSelector) *elapb.TrafficSelector {
	if ts == nil {
		return nil
	}

	return &elapb.TrafficSelector{
		Description: ts.Description,
		Macs:        toPBMACFilter(ts.MACs),
		Ip:          toPBIPFilter(ts.IP),
		Gtp:         toPBGTPFilter(ts.GTP),
	}
}

func toPBMACFilter(macf *cce.MACFilter) *elapb.MACFilter {
	if macf == nil {
		return nil
	}

	return &elapb.MACFilter{
		MacAddresses: macf.MACAddresses,
	}
}

func toPBIPFilter(ipf *cce.IPFilter) *elapb.IPFilter {
	if ipf == nil {
		return nil
	}

	// If the protocol is "all", make it empty in the protobuf
	// since there's currently no support for this on the other
	// end
	// TODO: remove this logic when other end supports the "all"
	// protocol value.
	protocol := ""
	switch {
	case ipf.Protocol != "all":
		protocol = ipf.Protocol
	}

	return &elapb.IPFilter{
		Address:   ipf.Address,
		Mask:      uint32(ipf.Mask),
		BeginPort: uint32(ipf.BeginPort),
		EndPort:   uint32(ipf.EndPort),
		Protocol:  protocol,
	}
}

func toPBGTPFilter(gtpf *cce.GTPFilter) *elapb.GTPFilter {
	if gtpf == nil {
		return nil
	}

	return &elapb.GTPFilter{
		Address: gtpf.Address,
		Mask:    uint32(gtpf.Mask),
		Imsis:   gtpf.IMSIs,
	}
}

func toPBTrafficTarget(target *cce.TrafficTarget) *elapb.TrafficTarget {
	if target == nil {
		return nil
	}

	return &elapb.TrafficTarget{
		Description: target.Description,
		Action:      toPBTargetAction(target.Action),
		Mac:         toPBMACModifier(target.MAC),
		Ip:          toPBIPModifier(target.IP),
	}
}

func toPBTargetAction(action string) elapb.TrafficTarget_TargetAction {
	switch action {
	case "accept":
		return elapb.TrafficTarget_ACCEPT
	case "reject":
		return elapb.TrafficTarget_REJECT
	case "drop":
		return elapb.TrafficTarget_DROP
	default:
		panic(fmt.Sprintf("invalid target action %s", action))
	}
}

func toPBMACModifier(macMod *cce.MACModifier) *elapb.MACModifier {
	if macMod == nil {
		return nil
	}

	return &elapb.MACModifier{
		MacAddress: macMod.MACAddress,
	}
}

func toPBIPModifier(ipMod *cce.IPModifier) *elapb.IPModifier {
	if ipMod == nil {
		return nil
	}

	return &elapb.IPModifier{
		Address: ipMod.Address,
		Port:    uint32(ipMod.Port),
	}
}
