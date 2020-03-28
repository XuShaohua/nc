// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// page can be read
pub const PROT_READ: i32 = 0x1;
/// page can be written
pub const PROT_WRITE: i32 = 0x2;
/// page can be executed
pub const PROT_EXEC: i32 = 0x4;
/// page may be used for atomic ops
pub const PROT_SEM: i32 = 0x8;
/// page can not be accessed
pub const PROT_NONE: i32 = 0x0;
/// mprotect flag: extend change to start of growsdown vma
pub const PROT_GROWSDOWN: i32 = 0x0100_0000;
/// mprotect flag: extend change to end of growsup vma
pub const PROT_GROWSUP: i32 = 0x0200_0000;

/// 0x01 - 0x03 are defined in linux/mman.h
/// Mask for type of mapping
pub const MAP_TYPE: i32 = 0x0f;
/// Interpret addr exactly
pub const MAP_FIXED: i32 = 0x10;
/// don't use a file
pub const MAP_ANONYMOUS: i32 = 0x20;
// TODO(Shaohua): CONFIG_MMAP_ALLOW_UNINITIALIZED
/// For anonymous mmap, memory could be uninitialized
pub const MAP_UNINITIALIZED: i32 = 0x400_0000;

/// 0x0100 - 0x80000 flags are defined in asm-generic/mman.h
/// MAP_FIXED which doesn't unmap underlying mapping
pub const MAP_FIXED_NOREPLACE: i32 = 0x100_000;

/// Flags for mlock
/// Lock pages in range after they are faulted in, do not prefault
pub const MLOCK_ONFAULT: i32 = 0x01;

/// sync memory asynchronously
pub const MS_ASYNC: i32 = 1;
/// invalidate the caches
pub const MS_INVALIDATE: i32 = 2;
/// synchronous memory sync
pub const MS_SYNC: i32 = 4;

/// no further special treatment
pub const MADV_NORMAL: i32 = 0;
/// expect random page references
pub const MADV_RANDOM: i32 = 1;
/// expect sequential page references
pub const MADV_SEQUENTIAL: i32 = 2;
/// will need these pages
pub const MADV_WILLNEED: i32 = 3;
/// don't need these pages
pub const MADV_DONTNEED: i32 = 4;

/// common parameters: try to keep these consistent across architectures
/// free pages only if memory pressure
pub const MADV_FREE: i32 = 8;
/// remove these pages & resources
pub const MADV_REMOVE: i32 = 9;
/// don't inherit across fork
pub const MADV_DONTFORK: i32 = 10;
/// do inherit across fork
pub const MADV_DOFORK: i32 = 11;
/// poison a page for testing
pub const MADV_HWPOISON: i32 = 100;
/// soft offline page for testing
pub const MADV_SOFT_OFFLINE: i32 = 101;

/// KSM may merge identical pages
pub const MADV_MERGEABLE: i32 = 12;
/// KSM may not merge identical pages
pub const MADV_UNMERGEABLE: i32 = 13;

/// Worth backing with hugepages
pub const MADV_HUGEPAGE: i32 = 14;
/// Not worth backing with hugepages
pub const MADV_NOHUGEPAGE: i32 = 15;

/// Explicity exclude from the core dump, overrides the coredump filter bits
pub const MADV_DONTDUMP: i32 = 16;
/// Clear the MADV_DONTDUMP flag
pub const MADV_DODUMP: i32 = 17;

/// Zero memory on fork, child only
pub const MADV_WIPEONFORK: i32 = 18;
/// Undo MADV_WIPEONFORK
pub const MADV_KEEPONFORK: i32 = 19;

/// compatibility flags
pub const MAP_FILE: i32 = 0;

pub const PKEY_DISABLE_ACCESS: i32 = 0x1;
pub const PKEY_DISABLE_WRITE: i32 = 0x2;
pub const PKEY_ACCESS_MASK: i32 = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;
