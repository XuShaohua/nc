// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From arch/arm64/include/asm/page-def.h

// TODO(Shaohua): Add build env to custom page shift.
pub const CONFIG_ARM64_PAGE_SHIFT: usize = 12;

/// PAGE_SHIFT determines the page size
pub const PAGE_SHIFT: usize = CONFIG_ARM64_PAGE_SHIFT;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = !(PAGE_SIZE - 1);
