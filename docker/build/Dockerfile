# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2019 Intel Corporation

# CCE API
FROM golang:1.12-alpine

ENV GO111MODULE on

WORKDIR /go/src/github.com/otcshare/edgecontroller

RUN apk add --no-cache git=2.24.3-r0

COPY go.mod .
COPY go.sum .

ARG GITHUB_TOKEN
ENV github_token=$GITHUB_TOKEN
RUN if [ -n "${github_token}" ]; \
	then git config --global url.https://${github_token}@github.com/.insteadOf https://github.com/; \
	fi;

RUN go mod download

COPY . .

RUN go build -o dist/cce ./cmd/cce && \
	cp dist/cce /cce

WORKDIR /artifacts

ENTRYPOINT ["/cce"]

CMD []
