// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use crate::restorefn_t;

extern "C" {
    fn __restore_rt();

    // TODO(Shaohua): Also export "__restore" function.
}

#[must_use]
#[inline]
pub fn get_sa_restorer() -> Option<restorefn_t> {
    Some(__restore_rt)
}
