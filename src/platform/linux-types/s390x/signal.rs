// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `arch/s390/include/asm/signal.h`
//!
//! S390 version
//! Derived from "include/asm-i386/signal.h"

/// at least 32 bits
pub type old_sigset_t = usize;

#[derive(Debug, Default, Clone)]
pub struct sigset_t {
    sig: [usize; _NSIG_WORDS],
}

impl From<old_sigset_t> for sigset_t {
    fn from(val: old_sigset_t) -> Self {
        let mut s = Self::default();
        s.sig[0] = val;
        s
    }
}
