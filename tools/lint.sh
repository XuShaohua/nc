#!/bin/bash
# Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
# Use of this source is governed by Apache-2.0 License that can be found
# in the LICENSE file.

# Lint all targets

set -xe

cargo clippy --all-targets --all-features -- \
  --deny warnings \
  --deny clippy::all \
  --deny clippy::cargo \
  --deny clippy::nursery \
  --deny clippy::pedantic
cargo fmt --check

