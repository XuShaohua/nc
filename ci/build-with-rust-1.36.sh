#!/bin/bash

set -xe

GID=$(id -g)
sudo docker run --user ${UID}:${GID} --rm --volume ${PWD}/:/nc \
  rust:1.36 /bin/bash -c 'cd /nc; cargo build'
