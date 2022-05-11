// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/page_64_types.h

use crate::types::page::PAGE_SIZE;

//TODO(Shaohua): handles `#ifdef CONFIG_KASAN`
pub const KASAN_STACK_ORDER: i32 = 1;

pub const THREAD_SIZE_ORDER: i32 = 2 + KASAN_STACK_ORDER;
pub const THREAD_SIZE: usize = PAGE_SIZE << THREAD_SIZE_ORDER;

pub const EXCEPTION_STACK_ORDER: i32 = 0 + KASAN_STACK_ORDER;
pub const EXCEPTION_STKSZ: usize = PAGE_SIZE << EXCEPTION_STACK_ORDER;

pub const IRQ_STACK_ORDER: i32 = 2 + KASAN_STACK_ORDER;
pub const IRQ_STACK_SIZE: usize = PAGE_SIZE << IRQ_STACK_ORDER;

/// The index for the tss.ist[] array. The hardware limit is 7 entries.
pub const IST_INDEX_DF: i32 = 0;
pub const IST_INDEX_NMI: i32 = 1;
pub const IST_INDEX_DB: i32 = 2;
pub const IST_INDEX_MCE: i32 = 3;
pub const IST_INDEX_VC: i32 = 4;

/// Set __PAGE_OFFSET to the most negative possible address +
/// PGDIR_SIZE*17 (pgd slot 273).
///
/// The gap is to allow a space for LDT remap for PTI (1 pgd slot) and space for
/// a hypervisor (16 slots). Choosing 16 slots for a hypervisor is arbitrary,
/// but it's what Xen requires.
pub const __PAGE_OFFSET_BASE_L5: usize = 0xff11_0000_0000_0000;
pub const __PAGE_OFFSET_BASE_L4: usize = 0xffff_8880_0000_0000;

// TODO(Shaohua): Handles #ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
pub const __PAGE_OFFSET: usize = __PAGE_OFFSET_BASE_L4;
//pub const __PAGE_OFFSET: usize = page_offset_base;

pub const __START_KERNEL_MAP: usize = 0xffff_ffff_8000_0000;

/// See Documentation/x86/x86_64/mm.rst for a description of the memory map.
pub const __PHYSICAL_MASK_SHIFT: i32 = 52;

//
// /*
//  * User space process size.  This is the first address outside the user range.
//  * There are a few constraints that determine this:
//  *
//  * On Intel CPUs, if a SYSCALL instruction is at the highest canonical
//  * address, then that syscall will enter the kernel with a
//  * non-canonical return address, and SYSRET will explode dangerously.
//  * We avoid this particular problem by preventing anything
//  * from being mapped at the maximum canonical address.
//  *
//  * On AMD CPUs in the Ryzen family, there's a nasty bug in which the
//  * CPUs malfunction if they execute code from the highest canonical page.
//  * They'll speculate right off the end of the canonical space, and
//  * bad things happen.  This is worked around in the same way as the
//  * Intel problem.
//  *
//  * With page table isolation enabled, we map the LDT in ... [stay tuned]
//  */
// #define TASK_SIZE_MAX	((_AC(1,UL) << __VIRTUAL_MASK_SHIFT) - PAGE_SIZE)
//
// #define DEFAULT_MAP_WINDOW	((1UL << 47) - PAGE_SIZE)
//
// /* This decides where the kernel will search for a free chunk of vm
//  * space during mmap's.
//  */
// #define IA32_PAGE_OFFSET	((current->personality & ADDR_LIMIT_3GB) ? \
// 					0xc0000000 : 0xFFFFe000)
//
// #define TASK_SIZE_LOW		(test_thread_flag(TIF_ADDR32) ? \
// 					IA32_PAGE_OFFSET : DEFAULT_MAP_WINDOW)
// #define TASK_SIZE		(test_thread_flag(TIF_ADDR32) ? \
// 					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
// #define TASK_SIZE_OF(child)	((test_tsk_thread_flag(child, TIF_ADDR32)) ? \
// 					IA32_PAGE_OFFSET : TASK_SIZE_MAX)
//
// pub const STACK_TOP: i32 = TASK_SIZE_LOW;
// pub const STACK_TOP_MAX: i32 = TASK_SIZE_MAX;
//
// // /*
// //  * In spite of the name, KERNEL_IMAGE_SIZE is a limit on the maximum virtual
// //  * address for the kernel image, rather than the limit on the size itself.
// //  * This can be at most 1 GiB, due to the fixmap living in the next 1 GiB (see
// //  * level2_kernel_pgt in arch/x86/kernel/head_64.S).
// //  *
// //  * On KASLR use 1 GiB by default, leaving 1 GiB for modules once the
// //  * page tables are fully set up.
// //  *
// //  * If KASLR is disabled we can shrink it to 0.5 GiB and increase the size
// //  * of the modules area to 1.5 GiB.
// //  */
// // #ifdef CONFIG_RANDOMIZE_BASE
// // #define KERNEL_IMAGE_SIZE	(1024 * 1024 * 1024)
// // #else
// // #define KERNEL_IMAGE_SIZE	(512 * 1024 * 1024)
// // #endif
