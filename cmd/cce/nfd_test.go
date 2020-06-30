// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main_test

import (
	"fmt"

	"github.com/open-ness/edgecontroller/swagger"
	"github.com/open-ness/edgecontroller/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("/nfd", func() {

	Describe("GET /nodes/{id}/nfd", func() {
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				nfdValue := uuid.New() // Any random string will do, we'll use it to compare

				entity := fmt.Sprintf(
					`'{"id": "%s", "node_id": "%s", "nfd_id": "test_tag", "nfd_value": "%s"}'`,
					uuid.New(), nodeCfg.nodeID, nfdValue)
				insertNFDTags(entity)

				nodeNfd := getNodeNFD(nodeCfg.nodeID)
				expected := &swagger.NodeNfdList{
					List: []swagger.NodeNfdTag{
						{
							ID:    "test_tag",
							Value: nfdValue,
						},
					},
				}
				Expect(nodeNfd).To(Equal(expected))
			},
			Entry("GET /nodes/{id}/nfd"),
		)
	})

})
