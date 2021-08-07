// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/page_32_types.h

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

pub const __START_KERNEL_map: usize = __PAGE_OFFSET;

pub const THREAD_SIZE_ORDER: i32 = 1;
pub const THREAD_SIZE: usize = PAGE_SIZE << THREAD_SIZE_ORDER;

pub const IRQ_STACK_SIZE: usize = THREAD_SIZE;

pub const N_EXCEPTION_STACKS: usize = 1;

// TODO(Shaohua): Handles `#ifdef CONFIG_X86_PAE`
/// This is beyond the 44 bit limit imposed by the 32bit long pfns,
/// but we need the full mask to make sure inverted PROT_NONE
/// entries have all the host bits set in a guest.
/// The real limit is still 44 bits.
pub const __PHYSICAL_MASK_SHIFT: i32 = 52;
pub const __VIRTUAL_MASK_SHIFT: i32 = 32;

//pub const __PHYSICAL_MASK_SHIFT: i32 = 32;
//pub const __VIRTUAL_MASK_SHIFT: i32 = 32;

/// User space process size: 3GB (default).
pub const IA32_PAGE_OFFSET: i32 = __PAGE_OFFSET;
pub const TASK_SIZE: i32 = __PAGE_OFFSET;
pub const TASK_SIZE_LOW: i32 = TASK_SIZE;
pub const TASK_SIZE_MAX: i32 = TASK_SIZE;
pub const DEFAULT_MAP_WINDOW: i32 = TASK_SIZE;
pub const STACK_TOP: i32 = TASK_SIZE;
pub const STACK_TOP_MAX: i32 = STACK_TOP;

/// In spite of the name, KERNEL_IMAGE_SIZE is a limit on the maximum virtual
/// address for the kernel image, rather than the limit on the size itself. On
/// 32-bit, this is not a strict limit, but this value is used to limit the
/// link-time virtual address range of the kernel, and by KASLR to limit the
/// randomized address from which the kernel is executed. A relocatable kernel
/// can be loaded somewhat higher than KERNEL_IMAGE_SIZE as long as enough space
/// remains for the vmalloc area.
pub const KERNEL_IMAGE_SIZE: usize = 512 * 1024 * 1024;
