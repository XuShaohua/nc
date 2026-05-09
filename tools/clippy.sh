#!/bin/bash

set -xe

cargo clippy --all-targets --fix --allow-dirty --allow-staged
