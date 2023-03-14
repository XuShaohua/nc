// Copyright (c) 2023 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `sys/_ucontext.h`

use crate::{__stack_t, mcontext_t, sigset_t};

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct ucontext_t {
    /// Keep the order of the first two fields.
    ///
    /// Also, keep them the first two fields in the structure.
    /// This way we can have a union with struct sigcontext and ucontext_t.
    /// This allows us to support them both at the same time.
    ///
    /// note: the union is not defined, though.
    pub uc_sigmask: sigset_t,
    pub uc_mcontext: mcontext_t,

    pub uc_link: *mut ucontext_t,
    pub uc_stack: __stack_t,
    pub uc_flags: i32,
    __spare__: [i32; 4],
}
