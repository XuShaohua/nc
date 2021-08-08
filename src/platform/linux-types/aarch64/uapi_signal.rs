// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/arm64/include/uapi/asm/signal.h

/// Required for AArch32 compatibility.
pub const SA_RESTORER: usize = 0x04000000;

pub const MINSIGSTKSZ: usize = 5120;
pub const SIGSTKSZ: usize = 16384;
