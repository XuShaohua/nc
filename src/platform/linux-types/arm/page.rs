// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `arch/arm/include/asm/page.h`

/// PAGE_SHIFT determines the page size
pub const PAGE_SHIFT: i32 = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !((1 << PAGE_SHIFT) - 1);
