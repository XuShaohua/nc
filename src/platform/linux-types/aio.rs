// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::signal::*;
use super::types::*;

// FROM fs/aio.c
#[repr(C)]
#[derive(Debug, Default)]
pub struct aio_sigset_t {
    pub sigmask: sigset_t,
    pub sigsetsize: size_t,
}
