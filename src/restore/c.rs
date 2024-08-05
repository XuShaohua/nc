// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use crate::sigaction_t, restorefn_t, SIGSEGV, rt_sigaction};

/// Reuse sa restorer function.
///
/// This method is unreliable.
#[must_use]
#[inline]
pub fn get_sa_restorer() -> Option<restorefn_t> {
    let mut old_sa = sigaction_t::default();
    let ret = unsafe { rt_sigaction(SIGSEGV, None, Some(&mut old_sa)) };
    if ret.is_ok() {
        old_sa.sa_restorer
    } else {
        None
    }
}
