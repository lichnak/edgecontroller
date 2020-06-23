# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2020 Intel Corporation

FROM ubuntu:18.04

RUN apt update && \
    apt install -y sudo

ARG username=vas
ARG user_dir=/home/$username

RUN useradd -d $user_dir -m -s /bin/bash $username
RUN usermod -aG sudo $username
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $username
WORKDIR $user_dir

COPY ./vas-sidecar ./
CMD ["sudo", "./vas-sidecar"]
