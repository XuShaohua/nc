// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/pgtable_32_types.h (incomplete)

use super::{PGDIR_SHIFT, PMD_SHIFT};

/// The Linux x86 paging architecture is 'compile-time dual-mode', it
/// implements both the traditional 2-level x86 page tables and the
/// newer 3-level PAE-mode page tables.
pub const PMD_SIZE: usize = 1 << PMD_SHIFT;
pub const PMD_MASK: usize = !(PMD_SIZE - 1);

pub const PGDIR_SIZE: usize = 1 << PGDIR_SHIFT;
pub const PGDIR_MASK: usize = !(PGDIR_SIZE - 1);
