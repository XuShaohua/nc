// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/page_types.h (incomplete)

use super::{PMD_SHIFT, __PAGE_OFFSET};

pub const PMD_PAGE_SIZE: usize = 1 << PMD_SHIFT;
pub const PMD_PAGE_MASK: usize = !(PMD_PAGE_SIZE - 1);

pub const HPAGE_SHIFT: i32 = PMD_SHIFT;
pub const HPAGE_SIZE: usize = 1 << HPAGE_SHIFT;
pub const HPAGE_MASK: usize = !(HPAGE_SIZE - 1);

pub const HUGE_MAX_HSTATE: i32 = 2;

pub const PAGE_OFFSET: usize = __PAGE_OFFSET;
