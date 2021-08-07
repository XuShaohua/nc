// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/arm64/include/uapi/asm/fcntl.h

/// Using our own definitions for AArch32 (compat) support.
/// must be a directory
pub const O_DIRECTORY: u32 = 0o40000;
/// don't follow links
pub const O_NOFOLLOW: u32 = 0o100000;
/// direct disk access hint - currently ignored
pub const O_DIRECT: u32 = 0o200000;
pub const O_LARGEFILE: u32 = 0o400000;
