// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/page_types.h (incomplete)

use super::{PMD_SHIFT, __PAGE_OFFSET};

/// PAGE_SHIFT determines the page size
pub const PAGE_SHIFT: i32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);

pub const PMD_PAGE_SIZE: usize = 1 << PMD_SHIFT;
pub const PMD_PAGE_MASK: usize = !(PMD_PAGE_SIZE - 1);

pub const HPAGE_SHIFT: i32 = PMD_SHIFT;
pub const HPAGE_SIZE: usize = 1 << HPAGE_SHIFT;
pub const HPAGE_MASK: usize = !(HPAGE_SIZE - 1);
pub const HUGETLB_PAGE_ORDER: i32 = HPAGE_SHIFT - PAGE_SHIFT;

pub const HUGE_MAX_HSTATE: i32 = 2;

pub const PAGE_OFFSET: usize = __PAGE_OFFSET;
