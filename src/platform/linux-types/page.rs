// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From include/asm-generic/page.h

/// Generic page.h implementation, for NOMMU architectures.
/// This provides the dummy definitions for the memory management.

/// PAGE_SHIFT determines the page size
pub const PAGE_SHIFT: i32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);

pub const PAGE_OFFSET: usize = 0;

pub const ARCH_PFN_OFFSET: usize = PAGE_OFFSET >> PAGE_SHIFT;
