// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From arch/x86/include/asm/pgtable_64_types.h (incomplete)

/// These are used to make use of C type-checking..
pub type pteval_t = usize;
pub type pmdval_t = usize;
pub type pudval_t = usize;
pub type p4dval_t = usize;
pub type pgdval_t = usize;
pub type pgprotval_t = usize;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pte_t {
    pub pte: pteval_t,
}

pub const SHARED_KERNEL_PMD: i32 = 0;

/// PGDIR_SHIFT determines what a top-level page table entry can map.
pub const PGDIR_SHIFT: i32 = 39;
pub const PTRS_PER_PGD: i32 = 512;
pub const MAX_PTRS_PER_P4D: i32 = 1;

/// 3rd level page
pub const PUD_SHIFT: i32 = 30;
pub const PTRS_PER_PUD: i32 = 512;

/// PMD_SHIFT determines the size of the area a middle-level page table can map.
pub const PMD_SHIFT: i32 = 21;
pub const PTRS_PER_PMD: i32 = 512;

/// entries per page directory level
pub const PTRS_PER_PTE: i32 = 512;

pub const PMD_SIZE: usize = 1 << PMD_SHIFT;
pub const PMD_MASK: usize = !(PMD_SIZE - 1);
pub const PUD_SIZE: usize = 1 << PUD_SHIFT;
pub const PUD_MASK: usize = !(PUD_SIZE - 1);
pub const PGDIR_SIZE: usize = 1 << PGDIR_SHIFT;
pub const PGDIR_MASK: usize = !(PGDIR_SIZE - 1);

// See Documentation/x86/x86_64/mm.rst for a description of the memory map.
//
// Be very careful vs. KASLR when changing anything here. The KASLR address
// range must not overlap with anything except the KASAN shadow area, which
// is correct as KASAN disables KASLR.
//pub const MAXMEM: usize = 1 << MAX_PHYSMEM_BITS;

pub const GUARD_HOLE_PGD_ENTRY: usize = -256isize as usize;
pub const GUARD_HOLE_SIZE: usize = 16 << PGDIR_SHIFT;
pub const GUARD_HOLE_BASE_ADDR: usize = GUARD_HOLE_PGD_ENTRY << PGDIR_SHIFT;
pub const GUARD_HOLE_END_ADDR: usize = GUARD_HOLE_BASE_ADDR + GUARD_HOLE_SIZE;

pub const LDT_PGD_ENTRY: usize = -240isize as usize;
pub const LDT_BASE_ADDR: usize = LDT_PGD_ENTRY << PGDIR_SHIFT;
pub const LDT_END_ADDR: usize = LDT_BASE_ADDR + PGDIR_SIZE;

pub const __VMALLOC_BASE_L4: usize = 0xffff_c900_0000_0000;
pub const __VMALLOC_BASE_L5: usize = 0xffa0_0000_0000_0000;

pub const VMALLOC_SIZE_TB_L4: usize = 32;
pub const VMALLOC_SIZE_TB_L5: usize = 12800;

pub const __VMEMMAP_BASE_L4: usize = 0xffff_ea00_0000_0000;
pub const __VMEMMAP_BASE_L5: usize = 0xffd4_0000_0000_0000;

// #ifdef CONFIG_DYNAMIC_MEMORY_LAYOUT
// # define VMALLOC_START		vmalloc_base
// # define VMALLOC_SIZE_TB	(pgtable_l5_enabled() ? VMALLOC_SIZE_TB_L5 : VMALLOC_SIZE_TB_L4)
// # define VMEMMAP_START		vmemmap_base
// #else
// # define VMALLOC_START		__VMALLOC_BASE_L4
// # define VMALLOC_SIZE_TB	VMALLOC_SIZE_TB_L4
// # define VMEMMAP_START		__VMEMMAP_BASE_L4
// #endif /* CONFIG_DYNAMIC_MEMORY_LAYOUT */
//
// #define VMALLOC_END		(VMALLOC_START + (VMALLOC_SIZE_TB << 40) - 1)
//
// #define MODULES_VADDR		(__START_KERNEL_map + KERNEL_IMAGE_SIZE)
// /// The module sections ends with the start of the fixmap
// #ifndef CONFIG_DEBUG_KMAP_LOCAL_FORCE_MAP
// # define MODULES_END		_AC(0xffffffffff000000, UL)
// #else
// # define MODULES_END		_AC(0xfffffffffe000000, UL)
// #endif
// #define MODULES_LEN		(MODULES_END - MODULES_VADDR)

pub const ESPFIX_PGD_ENTRY: usize = -2isize as usize;
//pub const ESPFIX_BASE_ADDR: usize = ESPFIX_PGD_ENTRY << P4D_SHIFT;

pub const CPU_ENTRY_AREA_PGD: usize = -4isize as usize;
//pub const CPU_ENTRY_AREA_BASE: usize = CPU_ENTRY_AREA_PGD << P4D_SHIFT;

pub const EFI_VA_START: usize = (-4isize * (1 << 30)) as usize;
pub const EFI_VA_END: usize = (-68isize * (1 << 30)) as usize;

pub const EARLY_DYNAMIC_PAGE_TABLES: i32 = 64;
