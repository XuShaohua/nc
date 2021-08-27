// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `arch/arm/include/asm/signal.h`

/// Most things should be clean enough to redefine this at will, if care
/// is taken to make libc match.

pub const _NSIG: usize = 64;
pub const _NSIG_BPW: usize = 32;
pub const _NSIG_WORDS: usize = _NSIG / _NSIG_BPW;

/// at least 32 bits
pub type old_sigset_t = usize;

#[repr(C)]
#[derive(Debug)]
pub struct sigset_t {
    pub sig: [usize; _NSIG_WORDS],
}
