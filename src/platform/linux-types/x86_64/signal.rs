// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `arch/x86/include/asm/signal.h`

/// Most things should be clean enough to redefine this at will, if care is taken to make libc match.
pub const _NSIG: usize = 64;

pub const _NSIG_BPW: usize = 64;

pub const _NSIG_WORDS: usize = _NSIG / _NSIG_BPW;

/// at least 32 bits
pub type old_sigset_t = usize;

#[repr(C)]
#[derive(Debug)]
pub struct sigset_t {
    pub sig: [usize; _NSIG_WORDS],
}

/// non-uapi in-kernel SA_FLAGS for those indicates ABI for a signal frame.
pub const SA_IA32_ABI: u32 = 0x02000000;
pub const SA_X32_ABI: u32 = 0x01000000;

pub type compat_sigset_t = sigset_t;
