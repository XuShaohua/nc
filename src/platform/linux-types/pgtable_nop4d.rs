// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `include/asm-generic/pgtable-nop4d.h`

use super::{pgd_t, PGDIR_SHIFT};

pub const __PAGETABLE_P4D_FOLDED: i32 = 1;

#[repr(C)]
#[derive(Debug)]
pub struct p4d_t {
    pub pgd: pgd_t,
}

pub const P4D_SHIFT: i32 = PGDIR_SHIFT;
pub const MAX_PTRS_PER_P4D: i32 = 1;
pub const PTRS_PER_P4D: i32 = 1;
pub const P4D_SIZE: usize = 1 << P4D_SHIFT;
pub const P4D_MASK: usize = !(P4D_SIZE - 1);
