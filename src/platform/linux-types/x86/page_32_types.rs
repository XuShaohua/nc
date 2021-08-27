// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/page_32_types.h (incomplete)

/// This handles the memory map.
///
/// A __PAGE_OFFSET of 0xC0000000 means that the kernel has
/// a virtual address space of one gigabyte, which limits the
/// amount of physical memory you can use to about 950MB.
///
/// If you want more physical memory than this then see the CONFIG_HIGHMEM4G
/// and CONFIG_HIGHMEM64G options in the kernel configuration.
pub const CONFIG_PAGE_OFFSET: usize = 0x80000000;
pub const __PAGE_OFFSET_BASE: usize = CONFIG_PAGE_OFFSET;
pub const __PAGE_OFFSET: usize = __PAGE_OFFSET_BASE;
